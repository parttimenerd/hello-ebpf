/** Auto-generated */
package me.bechberger.ebpf.runtime;

import me.bechberger.ebpf.annotations.EnumMember;
import me.bechberger.ebpf.annotations.InlineUnion;
import me.bechberger.ebpf.annotations.Offset;
import me.bechberger.ebpf.annotations.OriginalName;
import me.bechberger.ebpf.annotations.Size;
import me.bechberger.ebpf.annotations.Type;
import me.bechberger.ebpf.annotations.Unsigned;
import me.bechberger.ebpf.annotations.bpf.BuiltinBPFFunction;
import me.bechberger.ebpf.annotations.bpf.MethodIsBPFRelatedFunction;
import me.bechberger.ebpf.annotations.bpf.NotUsableInJava;
import me.bechberger.ebpf.type.Enum;
import me.bechberger.ebpf.type.Ptr;
import me.bechberger.ebpf.type.Struct;
import me.bechberger.ebpf.type.TypedEnum;
import me.bechberger.ebpf.type.TypedefBase;
import me.bechberger.ebpf.type.Union;
import org.jetbrains.annotations.Nullable;
import static me.bechberger.ebpf.runtime.AaDefinitions.*;
import static me.bechberger.ebpf.runtime.AafsDefinitions.*;
import static me.bechberger.ebpf.runtime.Aat2870Definitions.*;
import static me.bechberger.ebpf.runtime.AccountDefinitions.*;
import static me.bechberger.ebpf.runtime.AcctDefinitions.*;
import static me.bechberger.ebpf.runtime.AcompDefinitions.*;
import static me.bechberger.ebpf.runtime.AcpiDefinitions.*;
import static me.bechberger.ebpf.runtime.AcpiphpDefinitions.*;
import static me.bechberger.ebpf.runtime.ActionDefinitions.*;
import static me.bechberger.ebpf.runtime.ActiveDefinitions.*;
import static me.bechberger.ebpf.runtime.AddDefinitions.*;
import static me.bechberger.ebpf.runtime.AddrDefinitions.*;
import static me.bechberger.ebpf.runtime.AddrconfDefinitions.*;
import static me.bechberger.ebpf.runtime.AdjustDefinitions.*;
import static me.bechberger.ebpf.runtime.AdlDefinitions.*;
import static me.bechberger.ebpf.runtime.Adp5520Definitions.*;
import static me.bechberger.ebpf.runtime.AdvisorDefinitions.*;
import static me.bechberger.ebpf.runtime.AeadDefinitions.*;
import static me.bechberger.ebpf.runtime.AerDefinitions.*;
import static me.bechberger.ebpf.runtime.AgpDefinitions.*;
import static me.bechberger.ebpf.runtime.AhashDefinitions.*;
import static me.bechberger.ebpf.runtime.AioDefinitions.*;
import static me.bechberger.ebpf.runtime.AlarmDefinitions.*;
import static me.bechberger.ebpf.runtime.AllocDefinitions.*;
import static me.bechberger.ebpf.runtime.AllocateDefinitions.*;
import static me.bechberger.ebpf.runtime.AmdDefinitions.*;
import static me.bechberger.ebpf.runtime.AmlDefinitions.*;
import static me.bechberger.ebpf.runtime.AnonDefinitions.*;
import static me.bechberger.ebpf.runtime.ApeiDefinitions.*;
import static me.bechberger.ebpf.runtime.ApicDefinitions.*;
import static me.bechberger.ebpf.runtime.ApparmorDefinitions.*;
import static me.bechberger.ebpf.runtime.AppendDefinitions.*;
import static me.bechberger.ebpf.runtime.ApplyDefinitions.*;
import static me.bechberger.ebpf.runtime.ArchDefinitions.*;
import static me.bechberger.ebpf.runtime.ArenaDefinitions.*;
import static me.bechberger.ebpf.runtime.ArpDefinitions.*;
import static me.bechberger.ebpf.runtime.ArrayDefinitions.*;
import static me.bechberger.ebpf.runtime.Asn1Definitions.*;
import static me.bechberger.ebpf.runtime.AssocDefinitions.*;
import static me.bechberger.ebpf.runtime.AsymmetricDefinitions.*;
import static me.bechberger.ebpf.runtime.AsyncDefinitions.*;
import static me.bechberger.ebpf.runtime.AtaDefinitions.*;
import static me.bechberger.ebpf.runtime.AtkbdDefinitions.*;
import static me.bechberger.ebpf.runtime.AtomicDefinitions.*;
import static me.bechberger.ebpf.runtime.AttachDefinitions.*;
import static me.bechberger.ebpf.runtime.AttributeDefinitions.*;
import static me.bechberger.ebpf.runtime.AuditDefinitions.*;
import static me.bechberger.ebpf.runtime.AuxiliaryDefinitions.*;
import static me.bechberger.ebpf.runtime.AvailableDefinitions.*;
import static me.bechberger.ebpf.runtime.AvcDefinitions.*;
import static me.bechberger.ebpf.runtime.AvtabDefinitions.*;
import static me.bechberger.ebpf.runtime.BackingDefinitions.*;
import static me.bechberger.ebpf.runtime.BacklightDefinitions.*;
import static me.bechberger.ebpf.runtime.BadDefinitions.*;
import static me.bechberger.ebpf.runtime.BadblocksDefinitions.*;
import static me.bechberger.ebpf.runtime.BalanceDefinitions.*;
import static me.bechberger.ebpf.runtime.BalloonDefinitions.*;
import static me.bechberger.ebpf.runtime.BdevDefinitions.*;
import static me.bechberger.ebpf.runtime.BdiDefinitions.*;
import static me.bechberger.ebpf.runtime.BgpioDefinitions.*;
import static me.bechberger.ebpf.runtime.BhDefinitions.*;
import static me.bechberger.ebpf.runtime.BindDefinitions.*;
import static me.bechberger.ebpf.runtime.BioDefinitions.*;
import static me.bechberger.ebpf.runtime.BitmapDefinitions.*;
import static me.bechberger.ebpf.runtime.Blake2sDefinitions.*;
import static me.bechberger.ebpf.runtime.BlkDefinitions.*;
import static me.bechberger.ebpf.runtime.BlkcgDefinitions.*;
import static me.bechberger.ebpf.runtime.BlkdevDefinitions.*;
import static me.bechberger.ebpf.runtime.BlkgDefinitions.*;
import static me.bechberger.ebpf.runtime.BlkifDefinitions.*;
import static me.bechberger.ebpf.runtime.BlockDefinitions.*;
import static me.bechberger.ebpf.runtime.BloomDefinitions.*;
import static me.bechberger.ebpf.runtime.BootDefinitions.*;
import static me.bechberger.ebpf.runtime.BpfDefinitions.*;
import static me.bechberger.ebpf.runtime.BqlDefinitions.*;
import static me.bechberger.ebpf.runtime.BsgDefinitions.*;
import static me.bechberger.ebpf.runtime.BtfDefinitions.*;
import static me.bechberger.ebpf.runtime.BtreeDefinitions.*;
import static me.bechberger.ebpf.runtime.BtsDefinitions.*;
import static me.bechberger.ebpf.runtime.BufferDefinitions.*;
import static me.bechberger.ebpf.runtime.BuildDefinitions.*;
import static me.bechberger.ebpf.runtime.BusDefinitions.*;
import static me.bechberger.ebpf.runtime.BytDefinitions.*;
import static me.bechberger.ebpf.runtime.CacheDefinitions.*;
import static me.bechberger.ebpf.runtime.CalcDefinitions.*;
import static me.bechberger.ebpf.runtime.CalculateDefinitions.*;
import static me.bechberger.ebpf.runtime.CalipsoDefinitions.*;
import static me.bechberger.ebpf.runtime.CallDefinitions.*;
import static me.bechberger.ebpf.runtime.CanDefinitions.*;
import static me.bechberger.ebpf.runtime.CapDefinitions.*;
import static me.bechberger.ebpf.runtime.CcDefinitions.*;
import static me.bechberger.ebpf.runtime.CdevDefinitions.*;
import static me.bechberger.ebpf.runtime.CdromDefinitions.*;
import static me.bechberger.ebpf.runtime.CeaDefinitions.*;
import static me.bechberger.ebpf.runtime.Cfg80211Definitions.*;
import static me.bechberger.ebpf.runtime.Cgroup1Definitions.*;
import static me.bechberger.ebpf.runtime.CgroupDefinitions.*;
import static me.bechberger.ebpf.runtime.ChangeDefinitions.*;
import static me.bechberger.ebpf.runtime.ChargerDefinitions.*;
import static me.bechberger.ebpf.runtime.CheckDefinitions.*;
import static me.bechberger.ebpf.runtime.ChvDefinitions.*;
import static me.bechberger.ebpf.runtime.CipsoDefinitions.*;
import static me.bechberger.ebpf.runtime.ClassDefinitions.*;
import static me.bechberger.ebpf.runtime.CleanDefinitions.*;
import static me.bechberger.ebpf.runtime.CleanupDefinitions.*;
import static me.bechberger.ebpf.runtime.ClearDefinitions.*;
import static me.bechberger.ebpf.runtime.ClkDefinitions.*;
import static me.bechberger.ebpf.runtime.ClockeventsDefinitions.*;
import static me.bechberger.ebpf.runtime.ClocksourceDefinitions.*;
import static me.bechberger.ebpf.runtime.ClosureDefinitions.*;
import static me.bechberger.ebpf.runtime.CmaDefinitions.*;
import static me.bechberger.ebpf.runtime.CmciDefinitions.*;
import static me.bechberger.ebpf.runtime.CmdlineDefinitions.*;
import static me.bechberger.ebpf.runtime.CmisDefinitions.*;
import static me.bechberger.ebpf.runtime.CmosDefinitions.*;
import static me.bechberger.ebpf.runtime.CmpDefinitions.*;
import static me.bechberger.ebpf.runtime.CnDefinitions.*;
import static me.bechberger.ebpf.runtime.CollapseDefinitions.*;
import static me.bechberger.ebpf.runtime.CollectDefinitions.*;
import static me.bechberger.ebpf.runtime.CommonDefinitions.*;
import static me.bechberger.ebpf.runtime.CompactionDefinitions.*;
import static me.bechberger.ebpf.runtime.CompatDefinitions.*;
import static me.bechberger.ebpf.runtime.ComponentDefinitions.*;
import static me.bechberger.ebpf.runtime.ComputeDefinitions.*;
import static me.bechberger.ebpf.runtime.ConDefinitions.*;
import static me.bechberger.ebpf.runtime.CondDefinitions.*;
import static me.bechberger.ebpf.runtime.ConfigDefinitions.*;
import static me.bechberger.ebpf.runtime.ConfigfsDefinitions.*;
import static me.bechberger.ebpf.runtime.ConsoleDefinitions.*;
import static me.bechberger.ebpf.runtime.ContextDefinitions.*;
import static me.bechberger.ebpf.runtime.ConvertDefinitions.*;
import static me.bechberger.ebpf.runtime.CookieDefinitions.*;
import static me.bechberger.ebpf.runtime.CopyDefinitions.*;
import static me.bechberger.ebpf.runtime.CoreDefinitions.*;
import static me.bechberger.ebpf.runtime.CoredumpDefinitions.*;
import static me.bechberger.ebpf.runtime.CountDefinitions.*;
import static me.bechberger.ebpf.runtime.CpciDefinitions.*;
import static me.bechberger.ebpf.runtime.CperDefinitions.*;
import static me.bechberger.ebpf.runtime.CppcDefinitions.*;
import static me.bechberger.ebpf.runtime.CpuDefinitions.*;
import static me.bechberger.ebpf.runtime.CpuacctDefinitions.*;
import static me.bechberger.ebpf.runtime.CpufreqDefinitions.*;
import static me.bechberger.ebpf.runtime.CpuhpDefinitions.*;
import static me.bechberger.ebpf.runtime.CpuidleDefinitions.*;
import static me.bechberger.ebpf.runtime.CpumaskDefinitions.*;
import static me.bechberger.ebpf.runtime.CpusDefinitions.*;
import static me.bechberger.ebpf.runtime.CpusetDefinitions.*;
import static me.bechberger.ebpf.runtime.CrashDefinitions.*;
import static me.bechberger.ebpf.runtime.CrbDefinitions.*;
import static me.bechberger.ebpf.runtime.Crc64Definitions.*;
import static me.bechberger.ebpf.runtime.CreateDefinitions.*;
import static me.bechberger.ebpf.runtime.CryptoDefinitions.*;
import static me.bechberger.ebpf.runtime.CrystalcoveDefinitions.*;
import static me.bechberger.ebpf.runtime.CssDefinitions.*;
import static me.bechberger.ebpf.runtime.CsumDefinitions.*;
import static me.bechberger.ebpf.runtime.CtDefinitions.*;
import static me.bechberger.ebpf.runtime.CtrlDefinitions.*;
import static me.bechberger.ebpf.runtime.CtxDefinitions.*;
import static me.bechberger.ebpf.runtime.CurrentDefinitions.*;
import static me.bechberger.ebpf.runtime.CxlDefinitions.*;
import static me.bechberger.ebpf.runtime.DDefinitions.*;
import static me.bechberger.ebpf.runtime.Da903xDefinitions.*;
import static me.bechberger.ebpf.runtime.Da9052Definitions.*;
import static me.bechberger.ebpf.runtime.Da9063Definitions.*;
import static me.bechberger.ebpf.runtime.DataDefinitions.*;
import static me.bechberger.ebpf.runtime.DaxDefinitions.*;
import static me.bechberger.ebpf.runtime.DbcDefinitions.*;
import static me.bechberger.ebpf.runtime.DbgDefinitions.*;
import static me.bechberger.ebpf.runtime.DcbDefinitions.*;
import static me.bechberger.ebpf.runtime.DcbnlDefinitions.*;
import static me.bechberger.ebpf.runtime.DdDefinitions.*;
import static me.bechberger.ebpf.runtime.DdebugDefinitions.*;
import static me.bechberger.ebpf.runtime.DeadlineDefinitions.*;
import static me.bechberger.ebpf.runtime.DebugDefinitions.*;
import static me.bechberger.ebpf.runtime.DebugfsDefinitions.*;
import static me.bechberger.ebpf.runtime.DecDefinitions.*;
import static me.bechberger.ebpf.runtime.DefaultDefinitions.*;
import static me.bechberger.ebpf.runtime.DeferredDefinitions.*;
import static me.bechberger.ebpf.runtime.DeflateDefinitions.*;
import static me.bechberger.ebpf.runtime.DelayacctDefinitions.*;
import static me.bechberger.ebpf.runtime.DelayedDefinitions.*;
import static me.bechberger.ebpf.runtime.DeleteDefinitions.*;
import static me.bechberger.ebpf.runtime.DentryDefinitions.*;
import static me.bechberger.ebpf.runtime.DequeueDefinitions.*;
import static me.bechberger.ebpf.runtime.DescDefinitions.*;
import static me.bechberger.ebpf.runtime.DestroyDefinitions.*;
import static me.bechberger.ebpf.runtime.DetachDefinitions.*;
import static me.bechberger.ebpf.runtime.DevDefinitions.*;
import static me.bechberger.ebpf.runtime.DevcdDefinitions.*;
import static me.bechberger.ebpf.runtime.DevfreqDefinitions.*;
import static me.bechberger.ebpf.runtime.DeviceDefinitions.*;
import static me.bechberger.ebpf.runtime.DevlDefinitions.*;
import static me.bechberger.ebpf.runtime.DevlinkDefinitions.*;
import static me.bechberger.ebpf.runtime.DevmDefinitions.*;
import static me.bechberger.ebpf.runtime.DevptsDefinitions.*;
import static me.bechberger.ebpf.runtime.DevresDefinitions.*;
import static me.bechberger.ebpf.runtime.DhDefinitions.*;
import static me.bechberger.ebpf.runtime.DimDefinitions.*;
import static me.bechberger.ebpf.runtime.DisableDefinitions.*;
import static me.bechberger.ebpf.runtime.DiskDefinitions.*;
import static me.bechberger.ebpf.runtime.DispatchDefinitions.*;
import static me.bechberger.ebpf.runtime.DisplayidDefinitions.*;
import static me.bechberger.ebpf.runtime.DlDefinitions.*;
import static me.bechberger.ebpf.runtime.DmDefinitions.*;
import static me.bechberger.ebpf.runtime.DmaDefinitions.*;
import static me.bechberger.ebpf.runtime.DmabufDefinitions.*;
import static me.bechberger.ebpf.runtime.DmaengineDefinitions.*;
import static me.bechberger.ebpf.runtime.DmarDefinitions.*;
import static me.bechberger.ebpf.runtime.DmemDefinitions.*;
import static me.bechberger.ebpf.runtime.DmiDefinitions.*;
import static me.bechberger.ebpf.runtime.DnsDefinitions.*;
import static me.bechberger.ebpf.runtime.DoDefinitions.*;
import static me.bechberger.ebpf.runtime.DomainDefinitions.*;
import static me.bechberger.ebpf.runtime.DownDefinitions.*;
import static me.bechberger.ebpf.runtime.DpcDefinitions.*;
import static me.bechberger.ebpf.runtime.DpllDefinitions.*;
import static me.bechberger.ebpf.runtime.DpmDefinitions.*;
import static me.bechberger.ebpf.runtime.DquotDefinitions.*;
import static me.bechberger.ebpf.runtime.DrainDefinitions.*;
import static me.bechberger.ebpf.runtime.DrbgDefinitions.*;
import static me.bechberger.ebpf.runtime.DriverDefinitions.*;
import static me.bechberger.ebpf.runtime.DrmDefinitions.*;
import static me.bechberger.ebpf.runtime.DrmmDefinitions.*;
import static me.bechberger.ebpf.runtime.DropDefinitions.*;
import static me.bechberger.ebpf.runtime.DsaDefinitions.*;
import static me.bechberger.ebpf.runtime.DstDefinitions.*;
import static me.bechberger.ebpf.runtime.DummyDefinitions.*;
import static me.bechberger.ebpf.runtime.DummyconDefinitions.*;
import static me.bechberger.ebpf.runtime.DumpDefinitions.*;
import static me.bechberger.ebpf.runtime.DupDefinitions.*;
import static me.bechberger.ebpf.runtime.DvdDefinitions.*;
import static me.bechberger.ebpf.runtime.DwDefinitions.*;
import static me.bechberger.ebpf.runtime.Dwc2Definitions.*;
import static me.bechberger.ebpf.runtime.DxDefinitions.*;
import static me.bechberger.ebpf.runtime.DynDefinitions.*;
import static me.bechberger.ebpf.runtime.DyneventDefinitions.*;
import static me.bechberger.ebpf.runtime.EafnosupportDefinitions.*;
import static me.bechberger.ebpf.runtime.EarlyDefinitions.*;
import static me.bechberger.ebpf.runtime.EbitmapDefinitions.*;
import static me.bechberger.ebpf.runtime.EcDefinitions.*;
import static me.bechberger.ebpf.runtime.EccDefinitions.*;
import static me.bechberger.ebpf.runtime.EcryptfsDefinitions.*;
import static me.bechberger.ebpf.runtime.EdacDefinitions.*;
import static me.bechberger.ebpf.runtime.EddDefinitions.*;
import static me.bechberger.ebpf.runtime.EdidDefinitions.*;
import static me.bechberger.ebpf.runtime.EfiDefinitions.*;
import static me.bechberger.ebpf.runtime.EfivarDefinitions.*;
import static me.bechberger.ebpf.runtime.EfivarfsDefinitions.*;
import static me.bechberger.ebpf.runtime.EhciDefinitions.*;
import static me.bechberger.ebpf.runtime.ElantsDefinitions.*;
import static me.bechberger.ebpf.runtime.ElevatorDefinitions.*;
import static me.bechberger.ebpf.runtime.ElfDefinitions.*;
import static me.bechberger.ebpf.runtime.ElvDefinitions.*;
import static me.bechberger.ebpf.runtime.EmDefinitions.*;
import static me.bechberger.ebpf.runtime.EmitDefinitions.*;
import static me.bechberger.ebpf.runtime.EnableDefinitions.*;
import static me.bechberger.ebpf.runtime.EndDefinitions.*;
import static me.bechberger.ebpf.runtime.EnqueueDefinitions.*;
import static me.bechberger.ebpf.runtime.EpDefinitions.*;
import static me.bechberger.ebpf.runtime.EprobeDefinitions.*;
import static me.bechberger.ebpf.runtime.ErstDefinitions.*;
import static me.bechberger.ebpf.runtime.EspintcpDefinitions.*;
import static me.bechberger.ebpf.runtime.EthDefinitions.*;
import static me.bechberger.ebpf.runtime.EthnlDefinitions.*;
import static me.bechberger.ebpf.runtime.EthtoolDefinitions.*;
import static me.bechberger.ebpf.runtime.EvdevDefinitions.*;
import static me.bechberger.ebpf.runtime.EventDefinitions.*;
import static me.bechberger.ebpf.runtime.EventfdDefinitions.*;
import static me.bechberger.ebpf.runtime.EventfsDefinitions.*;
import static me.bechberger.ebpf.runtime.EvmDefinitions.*;
import static me.bechberger.ebpf.runtime.EvtchnDefinitions.*;
import static me.bechberger.ebpf.runtime.ExcDefinitions.*;
import static me.bechberger.ebpf.runtime.ExecmemDefinitions.*;
import static me.bechberger.ebpf.runtime.ExitDefinitions.*;
import static me.bechberger.ebpf.runtime.Ext4Definitions.*;
import static me.bechberger.ebpf.runtime.ExtconDefinitions.*;
import static me.bechberger.ebpf.runtime.FDefinitions.*;
import static me.bechberger.ebpf.runtime.FanotifyDefinitions.*;
import static me.bechberger.ebpf.runtime.FatDefinitions.*;
import static me.bechberger.ebpf.runtime.FaultDefinitions.*;
import static me.bechberger.ebpf.runtime.FauxDefinitions.*;
import static me.bechberger.ebpf.runtime.FbDefinitions.*;
import static me.bechberger.ebpf.runtime.FbconDefinitions.*;
import static me.bechberger.ebpf.runtime.FdtDefinitions.*;
import static me.bechberger.ebpf.runtime.FfDefinitions.*;
import static me.bechberger.ebpf.runtime.FgraphDefinitions.*;
import static me.bechberger.ebpf.runtime.Fib4Definitions.*;
import static me.bechberger.ebpf.runtime.Fib6Definitions.*;
import static me.bechberger.ebpf.runtime.FibDefinitions.*;
import static me.bechberger.ebpf.runtime.FifoDefinitions.*;
import static me.bechberger.ebpf.runtime.FileDefinitions.*;
import static me.bechberger.ebpf.runtime.FilemapDefinitions.*;
import static me.bechberger.ebpf.runtime.FilenameDefinitions.*;
import static me.bechberger.ebpf.runtime.FillDefinitions.*;
import static me.bechberger.ebpf.runtime.FilterDefinitions.*;
import static me.bechberger.ebpf.runtime.FindDefinitions.*;
import static me.bechberger.ebpf.runtime.FinishDefinitions.*;
import static me.bechberger.ebpf.runtime.FirmwareDefinitions.*;
import static me.bechberger.ebpf.runtime.FixedDefinitions.*;
import static me.bechberger.ebpf.runtime.FixupDefinitions.*;
import static me.bechberger.ebpf.runtime.FlowDefinitions.*;
import static me.bechberger.ebpf.runtime.FlushDefinitions.*;
import static me.bechberger.ebpf.runtime.FnDefinitions.*;
import static me.bechberger.ebpf.runtime.FolioDefinitions.*;
import static me.bechberger.ebpf.runtime.FollowDefinitions.*;
import static me.bechberger.ebpf.runtime.FopsDefinitions.*;
import static me.bechberger.ebpf.runtime.ForDefinitions.*;
import static me.bechberger.ebpf.runtime.ForceDefinitions.*;
import static me.bechberger.ebpf.runtime.FprobeDefinitions.*;
import static me.bechberger.ebpf.runtime.FpuDefinitions.*;
import static me.bechberger.ebpf.runtime.FredDefinitions.*;
import static me.bechberger.ebpf.runtime.FreeDefinitions.*;
import static me.bechberger.ebpf.runtime.FreezeDefinitions.*;
import static me.bechberger.ebpf.runtime.FreezerDefinitions.*;
import static me.bechberger.ebpf.runtime.FreqDefinitions.*;
import static me.bechberger.ebpf.runtime.FromDefinitions.*;
import static me.bechberger.ebpf.runtime.FsDefinitions.*;
import static me.bechberger.ebpf.runtime.FscryptDefinitions.*;
import static me.bechberger.ebpf.runtime.FseDefinitions.*;
import static me.bechberger.ebpf.runtime.FsnotifyDefinitions.*;
import static me.bechberger.ebpf.runtime.FsverityDefinitions.*;
import static me.bechberger.ebpf.runtime.FtraceDefinitions.*;
import static me.bechberger.ebpf.runtime.FullDefinitions.*;
import static me.bechberger.ebpf.runtime.FunctionDefinitions.*;
import static me.bechberger.ebpf.runtime.FuseDefinitions.*;
import static me.bechberger.ebpf.runtime.FutexDefinitions.*;
import static me.bechberger.ebpf.runtime.FwDefinitions.*;
import static me.bechberger.ebpf.runtime.FwnodeDefinitions.*;
import static me.bechberger.ebpf.runtime.GartDefinitions.*;
import static me.bechberger.ebpf.runtime.GcmDefinitions.*;
import static me.bechberger.ebpf.runtime.GenDefinitions.*;
import static me.bechberger.ebpf.runtime.GenericDefinitions.*;
import static me.bechberger.ebpf.runtime.GenlDefinitions.*;
import static me.bechberger.ebpf.runtime.GenpdDefinitions.*;
import static me.bechberger.ebpf.runtime.GenphyDefinitions.*;
import static me.bechberger.ebpf.runtime.GetDefinitions.*;
import static me.bechberger.ebpf.runtime.GhesDefinitions.*;
import static me.bechberger.ebpf.runtime.GnetDefinitions.*;
import static me.bechberger.ebpf.runtime.GnttabDefinitions.*;
import static me.bechberger.ebpf.runtime.GpioDefinitions.*;
import static me.bechberger.ebpf.runtime.GpiochipDefinitions.*;
import static me.bechberger.ebpf.runtime.GpiodDefinitions.*;
import static me.bechberger.ebpf.runtime.GpiolibDefinitions.*;
import static me.bechberger.ebpf.runtime.GroDefinitions.*;
import static me.bechberger.ebpf.runtime.GroupDefinitions.*;
import static me.bechberger.ebpf.runtime.GupDefinitions.*;
import static me.bechberger.ebpf.runtime.HandleDefinitions.*;
import static me.bechberger.ebpf.runtime.HandshakeDefinitions.*;
import static me.bechberger.ebpf.runtime.HasDefinitions.*;
import static me.bechberger.ebpf.runtime.HashDefinitions.*;
import static me.bechberger.ebpf.runtime.HcdDefinitions.*;
import static me.bechberger.ebpf.runtime.HctxDefinitions.*;
import static me.bechberger.ebpf.runtime.HdmiDefinitions.*;
import static me.bechberger.ebpf.runtime.HfiDefinitions.*;
import static me.bechberger.ebpf.runtime.HidDefinitions.*;
import static me.bechberger.ebpf.runtime.HistDefinitions.*;
import static me.bechberger.ebpf.runtime.HmacDefinitions.*;
import static me.bechberger.ebpf.runtime.HmatDefinitions.*;
import static me.bechberger.ebpf.runtime.HmmDefinitions.*;
import static me.bechberger.ebpf.runtime.HookDefinitions.*;
import static me.bechberger.ebpf.runtime.HpetDefinitions.*;
import static me.bechberger.ebpf.runtime.HrtimerDefinitions.*;
import static me.bechberger.ebpf.runtime.HsuDefinitions.*;
import static me.bechberger.ebpf.runtime.HswepDefinitions.*;
import static me.bechberger.ebpf.runtime.HtabDefinitions.*;
import static me.bechberger.ebpf.runtime.HteDefinitions.*;
import static me.bechberger.ebpf.runtime.HubDefinitions.*;
import static me.bechberger.ebpf.runtime.HufDefinitions.*;
import static me.bechberger.ebpf.runtime.HugepageDefinitions.*;
import static me.bechberger.ebpf.runtime.HugetlbDefinitions.*;
import static me.bechberger.ebpf.runtime.HugetlbfsDefinitions.*;
import static me.bechberger.ebpf.runtime.HvDefinitions.*;
import static me.bechberger.ebpf.runtime.HvcDefinitions.*;
import static me.bechberger.ebpf.runtime.HwDefinitions.*;
import static me.bechberger.ebpf.runtime.HwlatDefinitions.*;
import static me.bechberger.ebpf.runtime.HwmonDefinitions.*;
import static me.bechberger.ebpf.runtime.HybridDefinitions.*;
import static me.bechberger.ebpf.runtime.HypervDefinitions.*;
import static me.bechberger.ebpf.runtime.HypervisorDefinitions.*;
import static me.bechberger.ebpf.runtime.I2cDefinitions.*;
import static me.bechberger.ebpf.runtime.I2cdevDefinitions.*;
import static me.bechberger.ebpf.runtime.I8042Definitions.*;
import static me.bechberger.ebpf.runtime.Ia32Definitions.*;
import static me.bechberger.ebpf.runtime.IbDefinitions.*;
import static me.bechberger.ebpf.runtime.IccDefinitions.*;
import static me.bechberger.ebpf.runtime.IcmpDefinitions.*;
import static me.bechberger.ebpf.runtime.Icmpv6Definitions.*;
import static me.bechberger.ebpf.runtime.IcxDefinitions.*;
import static me.bechberger.ebpf.runtime.IdleDefinitions.*;
import static me.bechberger.ebpf.runtime.IdrDefinitions.*;
import static me.bechberger.ebpf.runtime.Ieee80211Definitions.*;
import static me.bechberger.ebpf.runtime.IflaDefinitions.*;
import static me.bechberger.ebpf.runtime.Igmp6Definitions.*;
import static me.bechberger.ebpf.runtime.IgmpDefinitions.*;
import static me.bechberger.ebpf.runtime.ImaDefinitions.*;
import static me.bechberger.ebpf.runtime.ImsttfbDefinitions.*;
import static me.bechberger.ebpf.runtime.In6Definitions.*;
import static me.bechberger.ebpf.runtime.InDefinitions.*;
import static me.bechberger.ebpf.runtime.IncDefinitions.*;
import static me.bechberger.ebpf.runtime.Inet6Definitions.*;
import static me.bechberger.ebpf.runtime.InetDefinitions.*;
import static me.bechberger.ebpf.runtime.InitDefinitions.*;
import static me.bechberger.ebpf.runtime.InodeDefinitions.*;
import static me.bechberger.ebpf.runtime.InotifyDefinitions.*;
import static me.bechberger.ebpf.runtime.InputDefinitions.*;
import static me.bechberger.ebpf.runtime.InsertDefinitions.*;
import static me.bechberger.ebpf.runtime.InsnDefinitions.*;
import static me.bechberger.ebpf.runtime.IntDefinitions.*;
import static me.bechberger.ebpf.runtime.IntegrityDefinitions.*;
import static me.bechberger.ebpf.runtime.IntelDefinitions.*;
import static me.bechberger.ebpf.runtime.IntervalDefinitions.*;
import static me.bechberger.ebpf.runtime.InvalidateDefinitions.*;
import static me.bechberger.ebpf.runtime.IoDefinitions.*;
import static me.bechberger.ebpf.runtime.Ioam6Definitions.*;
import static me.bechberger.ebpf.runtime.IoapicDefinitions.*;
import static me.bechberger.ebpf.runtime.IocDefinitions.*;
import static me.bechberger.ebpf.runtime.IocgDefinitions.*;
import static me.bechberger.ebpf.runtime.IoctlDefinitions.*;
import static me.bechberger.ebpf.runtime.IomapDefinitions.*;
import static me.bechberger.ebpf.runtime.IommuDefinitions.*;
import static me.bechberger.ebpf.runtime.IommufdDefinitions.*;
import static me.bechberger.ebpf.runtime.IopfDefinitions.*;
import static me.bechberger.ebpf.runtime.IoremapDefinitions.*;
import static me.bechberger.ebpf.runtime.IosfDefinitions.*;
import static me.bechberger.ebpf.runtime.IovDefinitions.*;
import static me.bechberger.ebpf.runtime.IovaDefinitions.*;
import static me.bechberger.ebpf.runtime.Ip4Definitions.*;
import static me.bechberger.ebpf.runtime.Ip6Definitions.*;
import static me.bechberger.ebpf.runtime.Ip6addrlblDefinitions.*;
import static me.bechberger.ebpf.runtime.Ip6mrDefinitions.*;
import static me.bechberger.ebpf.runtime.IpDefinitions.*;
import static me.bechberger.ebpf.runtime.IpcDefinitions.*;
import static me.bechberger.ebpf.runtime.IpeDefinitions.*;
import static me.bechberger.ebpf.runtime.IpmrDefinitions.*;
import static me.bechberger.ebpf.runtime.Ipv4Definitions.*;
import static me.bechberger.ebpf.runtime.Ipv6Definitions.*;
import static me.bechberger.ebpf.runtime.IrqDefinitions.*;
import static me.bechberger.ebpf.runtime.IrteDefinitions.*;
import static me.bechberger.ebpf.runtime.IsDefinitions.*;
import static me.bechberger.ebpf.runtime.IsaDefinitions.*;
import static me.bechberger.ebpf.runtime.IsolateDefinitions.*;
import static me.bechberger.ebpf.runtime.IterDefinitions.*;
import static me.bechberger.ebpf.runtime.IvbepDefinitions.*;
import static me.bechberger.ebpf.runtime.IwDefinitions.*;
import static me.bechberger.ebpf.runtime.JailhouseDefinitions.*;
import static me.bechberger.ebpf.runtime.Jbd2Definitions.*;
import static me.bechberger.ebpf.runtime.JentDefinitions.*;
import static me.bechberger.ebpf.runtime.JournalDefinitions.*;
import static me.bechberger.ebpf.runtime.JumpDefinitions.*;
import static me.bechberger.ebpf.runtime.KDefinitions.*;
import static me.bechberger.ebpf.runtime.KallsymsDefinitions.*;
import static me.bechberger.ebpf.runtime.KbdDefinitions.*;
import static me.bechberger.ebpf.runtime.KdbDefinitions.*;
import static me.bechberger.ebpf.runtime.KernDefinitions.*;
import static me.bechberger.ebpf.runtime.KernelDefinitions.*;
import static me.bechberger.ebpf.runtime.KernfsDefinitions.*;
import static me.bechberger.ebpf.runtime.KexecDefinitions.*;
import static me.bechberger.ebpf.runtime.KeyDefinitions.*;
import static me.bechberger.ebpf.runtime.KeyctlDefinitions.*;
import static me.bechberger.ebpf.runtime.KeyringDefinitions.*;
import static me.bechberger.ebpf.runtime.KfenceDefinitions.*;
import static me.bechberger.ebpf.runtime.KfifoDefinitions.*;
import static me.bechberger.ebpf.runtime.KfreeDefinitions.*;
import static me.bechberger.ebpf.runtime.KgdbDefinitions.*;
import static me.bechberger.ebpf.runtime.KgdbocDefinitions.*;
import static me.bechberger.ebpf.runtime.KhoDefinitions.*;
import static me.bechberger.ebpf.runtime.KillDefinitions.*;
import static me.bechberger.ebpf.runtime.KimageDefinitions.*;
import static me.bechberger.ebpf.runtime.KlistDefinitions.*;
import static me.bechberger.ebpf.runtime.KlpDefinitions.*;
import static me.bechberger.ebpf.runtime.KmallocDefinitions.*;
import static me.bechberger.ebpf.runtime.KmemDefinitions.*;
import static me.bechberger.ebpf.runtime.KmsgDefinitions.*;
import static me.bechberger.ebpf.runtime.KobjDefinitions.*;
import static me.bechberger.ebpf.runtime.KobjectDefinitions.*;
import static me.bechberger.ebpf.runtime.KprobeDefinitions.*;
import static me.bechberger.ebpf.runtime.KsmDefinitions.*;
import static me.bechberger.ebpf.runtime.KsysDefinitions.*;
import static me.bechberger.ebpf.runtime.KthreadDefinitions.*;
import static me.bechberger.ebpf.runtime.KtimeDefinitions.*;
import static me.bechberger.ebpf.runtime.KvmDefinitions.*;
import static me.bechberger.ebpf.runtime.L3mdevDefinitions.*;
import static me.bechberger.ebpf.runtime.LabelDefinitions.*;
import static me.bechberger.ebpf.runtime.LandlockDefinitions.*;
import static me.bechberger.ebpf.runtime.LapicDefinitions.*;
import static me.bechberger.ebpf.runtime.LdmDefinitions.*;
import static me.bechberger.ebpf.runtime.LdmaDefinitions.*;
import static me.bechberger.ebpf.runtime.LedDefinitions.*;
import static me.bechberger.ebpf.runtime.LedtrigDefinitions.*;
import static me.bechberger.ebpf.runtime.LegacyDefinitions.*;
import static me.bechberger.ebpf.runtime.LinearDefinitions.*;
import static me.bechberger.ebpf.runtime.LineeventDefinitions.*;
import static me.bechberger.ebpf.runtime.LinereqDefinitions.*;
import static me.bechberger.ebpf.runtime.LinkDefinitions.*;
import static me.bechberger.ebpf.runtime.LinuxDefinitions.*;
import static me.bechberger.ebpf.runtime.ListDefinitions.*;
import static me.bechberger.ebpf.runtime.LoadDefinitions.*;
import static me.bechberger.ebpf.runtime.LocalDefinitions.*;
import static me.bechberger.ebpf.runtime.LockDefinitions.*;
import static me.bechberger.ebpf.runtime.LocksDefinitions.*;
import static me.bechberger.ebpf.runtime.LockupDefinitions.*;
import static me.bechberger.ebpf.runtime.LogDefinitions.*;
import static me.bechberger.ebpf.runtime.LookupDefinitions.*;
import static me.bechberger.ebpf.runtime.LoopDefinitions.*;
import static me.bechberger.ebpf.runtime.Lp8788Definitions.*;
import static me.bechberger.ebpf.runtime.LpssDefinitions.*;
import static me.bechberger.ebpf.runtime.LruDefinitions.*;
import static me.bechberger.ebpf.runtime.LskcipherDefinitions.*;
import static me.bechberger.ebpf.runtime.LsmDefinitions.*;
import static me.bechberger.ebpf.runtime.LwtunnelDefinitions.*;
import static me.bechberger.ebpf.runtime.Lz4Definitions.*;
import static me.bechberger.ebpf.runtime.MachineDefinitions.*;
import static me.bechberger.ebpf.runtime.MacsecDefinitions.*;
import static me.bechberger.ebpf.runtime.MadviseDefinitions.*;
import static me.bechberger.ebpf.runtime.MakeDefinitions.*;
import static me.bechberger.ebpf.runtime.MapDefinitions.*;
import static me.bechberger.ebpf.runtime.MapleDefinitions.*;
import static me.bechberger.ebpf.runtime.MarkDefinitions.*;
import static me.bechberger.ebpf.runtime.MasDefinitions.*;
import static me.bechberger.ebpf.runtime.MatchDefinitions.*;
import static me.bechberger.ebpf.runtime.Max310xDefinitions.*;
import static me.bechberger.ebpf.runtime.Max77693Definitions.*;
import static me.bechberger.ebpf.runtime.Max8925Definitions.*;
import static me.bechberger.ebpf.runtime.Max8997Definitions.*;
import static me.bechberger.ebpf.runtime.Max8998Definitions.*;
import static me.bechberger.ebpf.runtime.MaxDefinitions.*;
import static me.bechberger.ebpf.runtime.MayDefinitions.*;
import static me.bechberger.ebpf.runtime.MaybeDefinitions.*;
import static me.bechberger.ebpf.runtime.MbDefinitions.*;
import static me.bechberger.ebpf.runtime.MbmDefinitions.*;
import static me.bechberger.ebpf.runtime.MboxDefinitions.*;
import static me.bechberger.ebpf.runtime.MceDefinitions.*;
import static me.bechberger.ebpf.runtime.McheckDefinitions.*;
import static me.bechberger.ebpf.runtime.MciDefinitions.*;
import static me.bechberger.ebpf.runtime.MctpDefinitions.*;
import static me.bechberger.ebpf.runtime.MctrlDefinitions.*;
import static me.bechberger.ebpf.runtime.MdDefinitions.*;
import static me.bechberger.ebpf.runtime.MddevDefinitions.*;
import static me.bechberger.ebpf.runtime.MdioDefinitions.*;
import static me.bechberger.ebpf.runtime.MdiobusDefinitions.*;
import static me.bechberger.ebpf.runtime.MemDefinitions.*;
import static me.bechberger.ebpf.runtime.MemblockDefinitions.*;
import static me.bechberger.ebpf.runtime.MemcgDefinitions.*;
import static me.bechberger.ebpf.runtime.MemcpyDefinitions.*;
import static me.bechberger.ebpf.runtime.MemmapDefinitions.*;
import static me.bechberger.ebpf.runtime.MemoryDefinitions.*;
import static me.bechberger.ebpf.runtime.MempoolDefinitions.*;
import static me.bechberger.ebpf.runtime.MemtypeDefinitions.*;
import static me.bechberger.ebpf.runtime.MigrateDefinitions.*;
import static me.bechberger.ebpf.runtime.MinDefinitions.*;
import static me.bechberger.ebpf.runtime.MipiDefinitions.*;
import static me.bechberger.ebpf.runtime.MiscDefinitions.*;
import static me.bechberger.ebpf.runtime.MldDefinitions.*;
import static me.bechberger.ebpf.runtime.MlsDefinitions.*;
import static me.bechberger.ebpf.runtime.MmDefinitions.*;
import static me.bechberger.ebpf.runtime.MmapDefinitions.*;
import static me.bechberger.ebpf.runtime.MmcDefinitions.*;
import static me.bechberger.ebpf.runtime.MmioDefinitions.*;
import static me.bechberger.ebpf.runtime.MmuDefinitions.*;
import static me.bechberger.ebpf.runtime.MntDefinitions.*;
import static me.bechberger.ebpf.runtime.ModDefinitions.*;
import static me.bechberger.ebpf.runtime.ModuleDefinitions.*;
import static me.bechberger.ebpf.runtime.MountDefinitions.*;
import static me.bechberger.ebpf.runtime.MousedevDefinitions.*;
import static me.bechberger.ebpf.runtime.MoveDefinitions.*;
import static me.bechberger.ebpf.runtime.MpDefinitions.*;
import static me.bechberger.ebpf.runtime.MpageDefinitions.*;
import static me.bechberger.ebpf.runtime.MpiDefinitions.*;
import static me.bechberger.ebpf.runtime.MpihelpDefinitions.*;
import static me.bechberger.ebpf.runtime.MpolDefinitions.*;
import static me.bechberger.ebpf.runtime.MptcpDefinitions.*;
import static me.bechberger.ebpf.runtime.MqDefinitions.*;
import static me.bechberger.ebpf.runtime.MqueueDefinitions.*;
import static me.bechberger.ebpf.runtime.MrDefinitions.*;
import static me.bechberger.ebpf.runtime.MsgDefinitions.*;
import static me.bechberger.ebpf.runtime.MsiDefinitions.*;
import static me.bechberger.ebpf.runtime.MsrDefinitions.*;
import static me.bechberger.ebpf.runtime.MtDefinitions.*;
import static me.bechberger.ebpf.runtime.MtreeDefinitions.*;
import static me.bechberger.ebpf.runtime.MtrrDefinitions.*;
import static me.bechberger.ebpf.runtime.MutexDefinitions.*;
import static me.bechberger.ebpf.runtime.NDefinitions.*;
import static me.bechberger.ebpf.runtime.NapiDefinitions.*;
import static me.bechberger.ebpf.runtime.NativeDefinitions.*;
import static me.bechberger.ebpf.runtime.NbconDefinitions.*;
import static me.bechberger.ebpf.runtime.NcsiDefinitions.*;
import static me.bechberger.ebpf.runtime.NdDefinitions.*;
import static me.bechberger.ebpf.runtime.NdiscDefinitions.*;
import static me.bechberger.ebpf.runtime.NeighDefinitions.*;
import static me.bechberger.ebpf.runtime.NetDefinitions.*;
import static me.bechberger.ebpf.runtime.NetifDefinitions.*;
import static me.bechberger.ebpf.runtime.NetkitDefinitions.*;
import static me.bechberger.ebpf.runtime.NetlblDefinitions.*;
import static me.bechberger.ebpf.runtime.NetlinkDefinitions.*;
import static me.bechberger.ebpf.runtime.NetnsDefinitions.*;
import static me.bechberger.ebpf.runtime.NetpollDefinitions.*;
import static me.bechberger.ebpf.runtime.NewDefinitions.*;
import static me.bechberger.ebpf.runtime.NextDefinitions.*;
import static me.bechberger.ebpf.runtime.NexthopDefinitions.*;
import static me.bechberger.ebpf.runtime.NfDefinitions.*;
import static me.bechberger.ebpf.runtime.Nfs4Definitions.*;
import static me.bechberger.ebpf.runtime.NfsDefinitions.*;
import static me.bechberger.ebpf.runtime.NhDefinitions.*;
import static me.bechberger.ebpf.runtime.NhmexDefinitions.*;
import static me.bechberger.ebpf.runtime.Nl80211Definitions.*;
import static me.bechberger.ebpf.runtime.NlaDefinitions.*;
import static me.bechberger.ebpf.runtime.NmiDefinitions.*;
import static me.bechberger.ebpf.runtime.NoDefinitions.*;
import static me.bechberger.ebpf.runtime.NodeDefinitions.*;
import static me.bechberger.ebpf.runtime.NoopDefinitions.*;
import static me.bechberger.ebpf.runtime.NotifyDefinitions.*;
import static me.bechberger.ebpf.runtime.NrDefinitions.*;
import static me.bechberger.ebpf.runtime.NsDefinitions.*;
import static me.bechberger.ebpf.runtime.NullDefinitions.*;
import static me.bechberger.ebpf.runtime.NumaDefinitions.*;
import static me.bechberger.ebpf.runtime.NumachipDefinitions.*;
import static me.bechberger.ebpf.runtime.NvdimmDefinitions.*;
import static me.bechberger.ebpf.runtime.NvmemDefinitions.*;
import static me.bechberger.ebpf.runtime.ObjDefinitions.*;
import static me.bechberger.ebpf.runtime.OctepDefinitions.*;
import static me.bechberger.ebpf.runtime.OdDefinitions.*;
import static me.bechberger.ebpf.runtime.OfDefinitions.*;
import static me.bechberger.ebpf.runtime.OhciDefinitions.*;
import static me.bechberger.ebpf.runtime.OldDefinitions.*;
import static me.bechberger.ebpf.runtime.OomDefinitions.*;
import static me.bechberger.ebpf.runtime.OpalDefinitions.*;
import static me.bechberger.ebpf.runtime.OpenDefinitions.*;
import static me.bechberger.ebpf.runtime.OppDefinitions.*;
import static me.bechberger.ebpf.runtime.OsnoiseDefinitions.*;
import static me.bechberger.ebpf.runtime.P4Definitions.*;
import static me.bechberger.ebpf.runtime.PacketDefinitions.*;
import static me.bechberger.ebpf.runtime.PadataDefinitions.*;
import static me.bechberger.ebpf.runtime.PageDefinitions.*;
import static me.bechberger.ebpf.runtime.PagemapDefinitions.*;
import static me.bechberger.ebpf.runtime.PagesDefinitions.*;
import static me.bechberger.ebpf.runtime.PalmasDefinitions.*;
import static me.bechberger.ebpf.runtime.PanelDefinitions.*;
import static me.bechberger.ebpf.runtime.ParamDefinitions.*;
import static me.bechberger.ebpf.runtime.ParseDefinitions.*;
import static me.bechberger.ebpf.runtime.PartDefinitions.*;
import static me.bechberger.ebpf.runtime.PathDefinitions.*;
import static me.bechberger.ebpf.runtime.PcapDefinitions.*;
import static me.bechberger.ebpf.runtime.PccDefinitions.*;
import static me.bechberger.ebpf.runtime.PciDefinitions.*;
import static me.bechberger.ebpf.runtime.PcibiosDefinitions.*;
import static me.bechberger.ebpf.runtime.PcieDefinitions.*;
import static me.bechberger.ebpf.runtime.PciehpDefinitions.*;
import static me.bechberger.ebpf.runtime.PcimDefinitions.*;
import static me.bechberger.ebpf.runtime.PcpuDefinitions.*;
import static me.bechberger.ebpf.runtime.PercpuDefinitions.*;
import static me.bechberger.ebpf.runtime.PerfDefinitions.*;
import static me.bechberger.ebpf.runtime.PfifoDefinitions.*;
import static me.bechberger.ebpf.runtime.PfnDefinitions.*;
import static me.bechberger.ebpf.runtime.PhyDefinitions.*;
import static me.bechberger.ebpf.runtime.PhysDefinitions.*;
import static me.bechberger.ebpf.runtime.PhysdevDefinitions.*;
import static me.bechberger.ebpf.runtime.PickDefinitions.*;
import static me.bechberger.ebpf.runtime.PidDefinitions.*;
import static me.bechberger.ebpf.runtime.PidfsDefinitions.*;
import static me.bechberger.ebpf.runtime.PidsDefinitions.*;
import static me.bechberger.ebpf.runtime.PiixDefinitions.*;
import static me.bechberger.ebpf.runtime.PinDefinitions.*;
import static me.bechberger.ebpf.runtime.PinconfDefinitions.*;
import static me.bechberger.ebpf.runtime.PinctrlDefinitions.*;
import static me.bechberger.ebpf.runtime.PingDefinitions.*;
import static me.bechberger.ebpf.runtime.PinmuxDefinitions.*;
import static me.bechberger.ebpf.runtime.PipeDefinitions.*;
import static me.bechberger.ebpf.runtime.PirqDefinitions.*;
import static me.bechberger.ebpf.runtime.Pkcs1padDefinitions.*;
import static me.bechberger.ebpf.runtime.Pkcs7Definitions.*;
import static me.bechberger.ebpf.runtime.PlatformDefinitions.*;
import static me.bechberger.ebpf.runtime.PldmfwDefinitions.*;
import static me.bechberger.ebpf.runtime.Pm860xDefinitions.*;
import static me.bechberger.ebpf.runtime.PmDefinitions.*;
import static me.bechberger.ebpf.runtime.PmcDefinitions.*;
import static me.bechberger.ebpf.runtime.PmdDefinitions.*;
import static me.bechberger.ebpf.runtime.PmuDefinitions.*;
import static me.bechberger.ebpf.runtime.PnpDefinitions.*;
import static me.bechberger.ebpf.runtime.PnpacpiDefinitions.*;
import static me.bechberger.ebpf.runtime.PolicyDefinitions.*;
import static me.bechberger.ebpf.runtime.PolicydbDefinitions.*;
import static me.bechberger.ebpf.runtime.PollDefinitions.*;
import static me.bechberger.ebpf.runtime.Poly1305Definitions.*;
import static me.bechberger.ebpf.runtime.PopulateDefinitions.*;
import static me.bechberger.ebpf.runtime.PortDefinitions.*;
import static me.bechberger.ebpf.runtime.PosixDefinitions.*;
import static me.bechberger.ebpf.runtime.PowerDefinitions.*;
import static me.bechberger.ebpf.runtime.PowercapDefinitions.*;
import static me.bechberger.ebpf.runtime.PppDefinitions.*;
import static me.bechberger.ebpf.runtime.PpsDefinitions.*;
import static me.bechberger.ebpf.runtime.PrDefinitions.*;
import static me.bechberger.ebpf.runtime.PrbDefinitions.*;
import static me.bechberger.ebpf.runtime.PreemptDefinitions.*;
import static me.bechberger.ebpf.runtime.PrepareDefinitions.*;
import static me.bechberger.ebpf.runtime.PrintDefinitions.*;
import static me.bechberger.ebpf.runtime.PrintkDefinitions.*;
import static me.bechberger.ebpf.runtime.ProbeDefinitions.*;
import static me.bechberger.ebpf.runtime.ProbestubDefinitions.*;
import static me.bechberger.ebpf.runtime.ProcDefinitions.*;
import static me.bechberger.ebpf.runtime.ProcessDefinitions.*;
import static me.bechberger.ebpf.runtime.ProfileDefinitions.*;
import static me.bechberger.ebpf.runtime.ProgDefinitions.*;
import static me.bechberger.ebpf.runtime.PropagateDefinitions.*;
import static me.bechberger.ebpf.runtime.ProtoDefinitions.*;
import static me.bechberger.ebpf.runtime.Ps2Definitions.*;
import static me.bechberger.ebpf.runtime.PseDefinitions.*;
import static me.bechberger.ebpf.runtime.PseudoDefinitions.*;
import static me.bechberger.ebpf.runtime.PsiDefinitions.*;
import static me.bechberger.ebpf.runtime.PskbDefinitions.*;
import static me.bechberger.ebpf.runtime.PstoreDefinitions.*;
import static me.bechberger.ebpf.runtime.PtDefinitions.*;
import static me.bechberger.ebpf.runtime.PtdumpDefinitions.*;
import static me.bechberger.ebpf.runtime.PteDefinitions.*;
import static me.bechberger.ebpf.runtime.PtiDefinitions.*;
import static me.bechberger.ebpf.runtime.PtpDefinitions.*;
import static me.bechberger.ebpf.runtime.PtraceDefinitions.*;
import static me.bechberger.ebpf.runtime.PtyDefinitions.*;
import static me.bechberger.ebpf.runtime.PushDefinitions.*;
import static me.bechberger.ebpf.runtime.PutDefinitions.*;
import static me.bechberger.ebpf.runtime.PvDefinitions.*;
import static me.bechberger.ebpf.runtime.PvclockDefinitions.*;
import static me.bechberger.ebpf.runtime.PwmDefinitions.*;
import static me.bechberger.ebpf.runtime.QdiscDefinitions.*;
import static me.bechberger.ebpf.runtime.QhDefinitions.*;
import static me.bechberger.ebpf.runtime.QiDefinitions.*;
import static me.bechberger.ebpf.runtime.QueueDefinitions.*;
import static me.bechberger.ebpf.runtime.QuirkDefinitions.*;
import static me.bechberger.ebpf.runtime.QuotaDefinitions.*;
import static me.bechberger.ebpf.runtime.RadixDefinitions.*;
import static me.bechberger.ebpf.runtime.RamfsDefinitions.*;
import static me.bechberger.ebpf.runtime.RandomDefinitions.*;
import static me.bechberger.ebpf.runtime.RangeDefinitions.*;
import static me.bechberger.ebpf.runtime.Raw6Definitions.*;
import static me.bechberger.ebpf.runtime.RawDefinitions.*;
import static me.bechberger.ebpf.runtime.Rawv6Definitions.*;
import static me.bechberger.ebpf.runtime.RbDefinitions.*;
import static me.bechberger.ebpf.runtime.Rc5t583Definitions.*;
import static me.bechberger.ebpf.runtime.RcuDefinitions.*;
import static me.bechberger.ebpf.runtime.RdevDefinitions.*;
import static me.bechberger.ebpf.runtime.RdmaDefinitions.*;
import static me.bechberger.ebpf.runtime.RdmacgDefinitions.*;
import static me.bechberger.ebpf.runtime.RdtDefinitions.*;
import static me.bechberger.ebpf.runtime.RdtgroupDefinitions.*;
import static me.bechberger.ebpf.runtime.ReadDefinitions.*;
import static me.bechberger.ebpf.runtime.ReclaimDefinitions.*;
import static me.bechberger.ebpf.runtime.RegDefinitions.*;
import static me.bechberger.ebpf.runtime.RegcacheDefinitions.*;
import static me.bechberger.ebpf.runtime.RegisterDefinitions.*;
import static me.bechberger.ebpf.runtime.RegmapDefinitions.*;
import static me.bechberger.ebpf.runtime.RegulatorDefinitions.*;
import static me.bechberger.ebpf.runtime.RelayDefinitions.*;
import static me.bechberger.ebpf.runtime.ReleaseDefinitions.*;
import static me.bechberger.ebpf.runtime.RemapDefinitions.*;
import static me.bechberger.ebpf.runtime.RemoveDefinitions.*;
import static me.bechberger.ebpf.runtime.ReplaceDefinitions.*;
import static me.bechberger.ebpf.runtime.ReportDefinitions.*;
import static me.bechberger.ebpf.runtime.RequestDefinitions.*;
import static me.bechberger.ebpf.runtime.ResctrlDefinitions.*;
import static me.bechberger.ebpf.runtime.ReserveDefinitions.*;
import static me.bechberger.ebpf.runtime.ResetDefinitions.*;
import static me.bechberger.ebpf.runtime.ResourceDefinitions.*;
import static me.bechberger.ebpf.runtime.RestoreDefinitions.*;
import static me.bechberger.ebpf.runtime.RestrictDefinitions.*;
import static me.bechberger.ebpf.runtime.ResumeDefinitions.*;
import static me.bechberger.ebpf.runtime.RethookDefinitions.*;
import static me.bechberger.ebpf.runtime.ReuseportDefinitions.*;
import static me.bechberger.ebpf.runtime.RfkillDefinitions.*;
import static me.bechberger.ebpf.runtime.RhashtableDefinitions.*;
import static me.bechberger.ebpf.runtime.RingDefinitions.*;
import static me.bechberger.ebpf.runtime.RingbufDefinitions.*;
import static me.bechberger.ebpf.runtime.RioDefinitions.*;
import static me.bechberger.ebpf.runtime.RngDefinitions.*;
import static me.bechberger.ebpf.runtime.RoleDefinitions.*;
import static me.bechberger.ebpf.runtime.RpcDefinitions.*;
import static me.bechberger.ebpf.runtime.RpmDefinitions.*;
import static me.bechberger.ebpf.runtime.RprocDefinitions.*;
import static me.bechberger.ebpf.runtime.RqDefinitions.*;
import static me.bechberger.ebpf.runtime.RsaDefinitions.*;
import static me.bechberger.ebpf.runtime.RsassaDefinitions.*;
import static me.bechberger.ebpf.runtime.RseqDefinitions.*;
import static me.bechberger.ebpf.runtime.RssDefinitions.*;
import static me.bechberger.ebpf.runtime.Rt6Definitions.*;
import static me.bechberger.ebpf.runtime.RtDefinitions.*;
import static me.bechberger.ebpf.runtime.RtcDefinitions.*;
import static me.bechberger.ebpf.runtime.RtmDefinitions.*;
import static me.bechberger.ebpf.runtime.RtnetlinkDefinitions.*;
import static me.bechberger.ebpf.runtime.RtnlDefinitions.*;
import static me.bechberger.ebpf.runtime.RunDefinitions.*;
import static me.bechberger.ebpf.runtime.RustDefinitions.*;
import static me.bechberger.ebpf.runtime.RvDefinitions.*;
import static me.bechberger.ebpf.runtime.RxDefinitions.*;
import static me.bechberger.ebpf.runtime.SDefinitions.*;
import static me.bechberger.ebpf.runtime.SataDefinitions.*;
import static me.bechberger.ebpf.runtime.SaveDefinitions.*;
import static me.bechberger.ebpf.runtime.SavedDefinitions.*;
import static me.bechberger.ebpf.runtime.SbitmapDefinitions.*;
import static me.bechberger.ebpf.runtime.ScanDefinitions.*;
import static me.bechberger.ebpf.runtime.SccnxpDefinitions.*;
import static me.bechberger.ebpf.runtime.SchedDefinitions.*;
import static me.bechberger.ebpf.runtime.ScheduleDefinitions.*;
import static me.bechberger.ebpf.runtime.ScmDefinitions.*;
import static me.bechberger.ebpf.runtime.ScsiDefinitions.*;
import static me.bechberger.ebpf.runtime.SctpDefinitions.*;
import static me.bechberger.ebpf.runtime.ScxDefinitions.*;
import static me.bechberger.ebpf.runtime.SdDefinitions.*;
import static me.bechberger.ebpf.runtime.SdevDefinitions.*;
import static me.bechberger.ebpf.runtime.SdioDefinitions.*;
import static me.bechberger.ebpf.runtime.SeccompDefinitions.*;
import static me.bechberger.ebpf.runtime.SecurityDefinitions.*;
import static me.bechberger.ebpf.runtime.Seg6Definitions.*;
import static me.bechberger.ebpf.runtime.SelDefinitions.*;
import static me.bechberger.ebpf.runtime.SelectDefinitions.*;
import static me.bechberger.ebpf.runtime.SelinuxDefinitions.*;
import static me.bechberger.ebpf.runtime.SendDefinitions.*;
import static me.bechberger.ebpf.runtime.SeqDefinitions.*;
import static me.bechberger.ebpf.runtime.SerdevDefinitions.*;
import static me.bechberger.ebpf.runtime.Serial8250Definitions.*;
import static me.bechberger.ebpf.runtime.SerialDefinitions.*;
import static me.bechberger.ebpf.runtime.SerioDefinitions.*;
import static me.bechberger.ebpf.runtime.SetDefinitions.*;
import static me.bechberger.ebpf.runtime.SetupDefinitions.*;
import static me.bechberger.ebpf.runtime.SevDefinitions.*;
import static me.bechberger.ebpf.runtime.SfpDefinitions.*;
import static me.bechberger.ebpf.runtime.SgDefinitions.*;
import static me.bechberger.ebpf.runtime.SgxDefinitions.*;
import static me.bechberger.ebpf.runtime.Sha1Definitions.*;
import static me.bechberger.ebpf.runtime.Sha256Definitions.*;
import static me.bechberger.ebpf.runtime.Sha512Definitions.*;
import static me.bechberger.ebpf.runtime.ShashDefinitions.*;
import static me.bechberger.ebpf.runtime.ShmDefinitions.*;
import static me.bechberger.ebpf.runtime.ShmemDefinitions.*;
import static me.bechberger.ebpf.runtime.ShouldDefinitions.*;
import static me.bechberger.ebpf.runtime.ShowDefinitions.*;
import static me.bechberger.ebpf.runtime.ShpchpDefinitions.*;
import static me.bechberger.ebpf.runtime.ShrinkDefinitions.*;
import static me.bechberger.ebpf.runtime.SidtabDefinitions.*;
import static me.bechberger.ebpf.runtime.SimpleDefinitions.*;
import static me.bechberger.ebpf.runtime.SingleDefinitions.*;
import static me.bechberger.ebpf.runtime.SisDefinitions.*;
import static me.bechberger.ebpf.runtime.SkDefinitions.*;
import static me.bechberger.ebpf.runtime.SkbDefinitions.*;
import static me.bechberger.ebpf.runtime.SkcipherDefinitions.*;
import static me.bechberger.ebpf.runtime.SkxDefinitions.*;
import static me.bechberger.ebpf.runtime.SlabDefinitions.*;
import static me.bechberger.ebpf.runtime.SmackDefinitions.*;
import static me.bechberger.ebpf.runtime.SmeDefinitions.*;
import static me.bechberger.ebpf.runtime.SmkDefinitions.*;
import static me.bechberger.ebpf.runtime.SmpDefinitions.*;
import static me.bechberger.ebpf.runtime.SnapshotDefinitions.*;
import static me.bechberger.ebpf.runtime.SnbDefinitions.*;
import static me.bechberger.ebpf.runtime.SnbepDefinitions.*;
import static me.bechberger.ebpf.runtime.SnpDefinitions.*;
import static me.bechberger.ebpf.runtime.SnrDefinitions.*;
import static me.bechberger.ebpf.runtime.SocDefinitions.*;
import static me.bechberger.ebpf.runtime.SockDefinitions.*;
import static me.bechberger.ebpf.runtime.SoftwareDefinitions.*;
import static me.bechberger.ebpf.runtime.SparseDefinitions.*;
import static me.bechberger.ebpf.runtime.SpiDefinitions.*;
import static me.bechberger.ebpf.runtime.SpliceDefinitions.*;
import static me.bechberger.ebpf.runtime.SplitDefinitions.*;
import static me.bechberger.ebpf.runtime.SprDefinitions.*;
import static me.bechberger.ebpf.runtime.SquashfsDefinitions.*;
import static me.bechberger.ebpf.runtime.SrDefinitions.*;
import static me.bechberger.ebpf.runtime.SramDefinitions.*;
import static me.bechberger.ebpf.runtime.SrcuDefinitions.*;
import static me.bechberger.ebpf.runtime.SriovDefinitions.*;
import static me.bechberger.ebpf.runtime.StackDefinitions.*;
import static me.bechberger.ebpf.runtime.StartDefinitions.*;
import static me.bechberger.ebpf.runtime.StatDefinitions.*;
import static me.bechberger.ebpf.runtime.StaticDefinitions.*;
import static me.bechberger.ebpf.runtime.StatsDefinitions.*;
import static me.bechberger.ebpf.runtime.StopDefinitions.*;
import static me.bechberger.ebpf.runtime.StoreDefinitions.*;
import static me.bechberger.ebpf.runtime.StripeDefinitions.*;
import static me.bechberger.ebpf.runtime.StrpDefinitions.*;
import static me.bechberger.ebpf.runtime.SubflowDefinitions.*;
import static me.bechberger.ebpf.runtime.SubmitDefinitions.*;
import static me.bechberger.ebpf.runtime.SugovDefinitions.*;
import static me.bechberger.ebpf.runtime.SuperDefinitions.*;
import static me.bechberger.ebpf.runtime.SuspendDefinitions.*;
import static me.bechberger.ebpf.runtime.SvcDefinitions.*;
import static me.bechberger.ebpf.runtime.SvsmDefinitions.*;
import static me.bechberger.ebpf.runtime.SwDefinitions.*;
import static me.bechberger.ebpf.runtime.SwapDefinitions.*;
import static me.bechberger.ebpf.runtime.SwiotlbDefinitions.*;
import static me.bechberger.ebpf.runtime.SwitchDefinitions.*;
import static me.bechberger.ebpf.runtime.SwitchdevDefinitions.*;
import static me.bechberger.ebpf.runtime.SwsuspDefinitions.*;
import static me.bechberger.ebpf.runtime.Sx150xDefinitions.*;
import static me.bechberger.ebpf.runtime.SyncDefinitions.*;
import static me.bechberger.ebpf.runtime.SynchronizeDefinitions.*;
import static me.bechberger.ebpf.runtime.SynthDefinitions.*;
import static me.bechberger.ebpf.runtime.SysDefinitions.*;
import static me.bechberger.ebpf.runtime.SyscallDefinitions.*;
import static me.bechberger.ebpf.runtime.SysctlDefinitions.*;
import static me.bechberger.ebpf.runtime.SysfsDefinitions.*;
import static me.bechberger.ebpf.runtime.SysrqDefinitions.*;
import static me.bechberger.ebpf.runtime.SystemDefinitions.*;
import static me.bechberger.ebpf.runtime.SysvecDefinitions.*;
import static me.bechberger.ebpf.runtime.TargetDefinitions.*;
import static me.bechberger.ebpf.runtime.TaskDefinitions.*;
import static me.bechberger.ebpf.runtime.TaskletDefinitions.*;
import static me.bechberger.ebpf.runtime.TbootDefinitions.*;
import static me.bechberger.ebpf.runtime.TcDefinitions.*;
import static me.bechberger.ebpf.runtime.TcfDefinitions.*;
import static me.bechberger.ebpf.runtime.TcpDefinitions.*;
import static me.bechberger.ebpf.runtime.TcxDefinitions.*;
import static me.bechberger.ebpf.runtime.TdhDefinitions.*;
import static me.bechberger.ebpf.runtime.TdxDefinitions.*;
import static me.bechberger.ebpf.runtime.TestDefinitions.*;
import static me.bechberger.ebpf.runtime.TextDefinitions.*;
import static me.bechberger.ebpf.runtime.TgDefinitions.*;
import static me.bechberger.ebpf.runtime.ThermalDefinitions.*;
import static me.bechberger.ebpf.runtime.ThreadDefinitions.*;
import static me.bechberger.ebpf.runtime.ThrotlDefinitions.*;
import static me.bechberger.ebpf.runtime.TickDefinitions.*;
import static me.bechberger.ebpf.runtime.TimekeepingDefinitions.*;
import static me.bechberger.ebpf.runtime.TimensDefinitions.*;
import static me.bechberger.ebpf.runtime.TimerDefinitions.*;
import static me.bechberger.ebpf.runtime.TimerfdDefinitions.*;
import static me.bechberger.ebpf.runtime.TimerlatDefinitions.*;
import static me.bechberger.ebpf.runtime.TkDefinitions.*;
import static me.bechberger.ebpf.runtime.TlbDefinitions.*;
import static me.bechberger.ebpf.runtime.TlsDefinitions.*;
import static me.bechberger.ebpf.runtime.TmigrDefinitions.*;
import static me.bechberger.ebpf.runtime.TnumDefinitions.*;
import static me.bechberger.ebpf.runtime.ToDefinitions.*;
import static me.bechberger.ebpf.runtime.TomoyoDefinitions.*;
import static me.bechberger.ebpf.runtime.TopologyDefinitions.*;
import static me.bechberger.ebpf.runtime.TouchDefinitions.*;
import static me.bechberger.ebpf.runtime.TpacketDefinitions.*;
import static me.bechberger.ebpf.runtime.Tpm1Definitions.*;
import static me.bechberger.ebpf.runtime.Tpm2Definitions.*;
import static me.bechberger.ebpf.runtime.TpmDefinitions.*;
import static me.bechberger.ebpf.runtime.Tps6586xDefinitions.*;
import static me.bechberger.ebpf.runtime.Tps65910Definitions.*;
import static me.bechberger.ebpf.runtime.TraceDefinitions.*;
import static me.bechberger.ebpf.runtime.TracefsDefinitions.*;
import static me.bechberger.ebpf.runtime.TraceiterDefinitions.*;
import static me.bechberger.ebpf.runtime.TracepointDefinitions.*;
import static me.bechberger.ebpf.runtime.TraceprobeDefinitions.*;
import static me.bechberger.ebpf.runtime.TracerDefinitions.*;
import static me.bechberger.ebpf.runtime.TracingDefinitions.*;
import static me.bechberger.ebpf.runtime.TransportDefinitions.*;
import static me.bechberger.ebpf.runtime.TrieDefinitions.*;
import static me.bechberger.ebpf.runtime.TruncateDefinitions.*;
import static me.bechberger.ebpf.runtime.TrustedDefinitions.*;
import static me.bechberger.ebpf.runtime.TryDefinitions.*;
import static me.bechberger.ebpf.runtime.TscDefinitions.*;
import static me.bechberger.ebpf.runtime.TtyDefinitions.*;
import static me.bechberger.ebpf.runtime.TtyportDefinitions.*;
import static me.bechberger.ebpf.runtime.TunDefinitions.*;
import static me.bechberger.ebpf.runtime.Twl4030Definitions.*;
import static me.bechberger.ebpf.runtime.Twl6040Definitions.*;
import static me.bechberger.ebpf.runtime.TwlDefinitions.*;
import static me.bechberger.ebpf.runtime.TxDefinitions.*;
import static me.bechberger.ebpf.runtime.TypeDefinitions.*;
import static me.bechberger.ebpf.runtime.UDefinitions.*;
import static me.bechberger.ebpf.runtime.UartDefinitions.*;
import static me.bechberger.ebpf.runtime.UbsanDefinitions.*;
import static me.bechberger.ebpf.runtime.Udp4Definitions.*;
import static me.bechberger.ebpf.runtime.Udp6Definitions.*;
import static me.bechberger.ebpf.runtime.UdpDefinitions.*;
import static me.bechberger.ebpf.runtime.Udpv6Definitions.*;
import static me.bechberger.ebpf.runtime.UhciDefinitions.*;
import static me.bechberger.ebpf.runtime.UinputDefinitions.*;
import static me.bechberger.ebpf.runtime.UncoreDefinitions.*;
import static me.bechberger.ebpf.runtime.Univ8250Definitions.*;
import static me.bechberger.ebpf.runtime.UnixDefinitions.*;
import static me.bechberger.ebpf.runtime.UnlockDefinitions.*;
import static me.bechberger.ebpf.runtime.UnmapDefinitions.*;
import static me.bechberger.ebpf.runtime.UnregisterDefinitions.*;
import static me.bechberger.ebpf.runtime.UpdateDefinitions.*;
import static me.bechberger.ebpf.runtime.UprobeDefinitions.*;
import static me.bechberger.ebpf.runtime.UsbDefinitions.*;
import static me.bechberger.ebpf.runtime.UsbdevfsDefinitions.*;
import static me.bechberger.ebpf.runtime.UserDefinitions.*;
import static me.bechberger.ebpf.runtime.UserfaultfdDefinitions.*;
import static me.bechberger.ebpf.runtime.Utf8Definitions.*;
import static me.bechberger.ebpf.runtime.UvDefinitions.*;
import static me.bechberger.ebpf.runtime.UvhDefinitions.*;
import static me.bechberger.ebpf.runtime.ValidateDefinitions.*;
import static me.bechberger.ebpf.runtime.VcDefinitions.*;
import static me.bechberger.ebpf.runtime.VcapDefinitions.*;
import static me.bechberger.ebpf.runtime.VcpuDefinitions.*;
import static me.bechberger.ebpf.runtime.VcsDefinitions.*;
import static me.bechberger.ebpf.runtime.VdsoDefinitions.*;
import static me.bechberger.ebpf.runtime.VerifyDefinitions.*;
import static me.bechberger.ebpf.runtime.VfatDefinitions.*;
import static me.bechberger.ebpf.runtime.VfsDefinitions.*;
import static me.bechberger.ebpf.runtime.VgaDefinitions.*;
import static me.bechberger.ebpf.runtime.VgaconDefinitions.*;
import static me.bechberger.ebpf.runtime.ViaDefinitions.*;
import static me.bechberger.ebpf.runtime.ViommuDefinitions.*;
import static me.bechberger.ebpf.runtime.VirtDefinitions.*;
import static me.bechberger.ebpf.runtime.VirtblkDefinitions.*;
import static me.bechberger.ebpf.runtime.VirtioDefinitions.*;
import static me.bechberger.ebpf.runtime.VirtnetDefinitions.*;
import static me.bechberger.ebpf.runtime.VirtqueueDefinitions.*;
import static me.bechberger.ebpf.runtime.VirtscsiDefinitions.*;
import static me.bechberger.ebpf.runtime.VlanDefinitions.*;
import static me.bechberger.ebpf.runtime.VliDefinitions.*;
import static me.bechberger.ebpf.runtime.VmDefinitions.*;
import static me.bechberger.ebpf.runtime.VmaDefinitions.*;
import static me.bechberger.ebpf.runtime.VmallocDefinitions.*;
import static me.bechberger.ebpf.runtime.VmapDefinitions.*;
import static me.bechberger.ebpf.runtime.VmeDefinitions.*;
import static me.bechberger.ebpf.runtime.VmemmapDefinitions.*;
import static me.bechberger.ebpf.runtime.VmpressureDefinitions.*;
import static me.bechberger.ebpf.runtime.VmstatDefinitions.*;
import static me.bechberger.ebpf.runtime.VmwareDefinitions.*;
import static me.bechberger.ebpf.runtime.VpDefinitions.*;
import static me.bechberger.ebpf.runtime.VringDefinitions.*;
import static me.bechberger.ebpf.runtime.VtDefinitions.*;
import static me.bechberger.ebpf.runtime.WaitDefinitions.*;
import static me.bechberger.ebpf.runtime.WakeDefinitions.*;
import static me.bechberger.ebpf.runtime.WakeupDefinitions.*;
import static me.bechberger.ebpf.runtime.WalkDefinitions.*;
import static me.bechberger.ebpf.runtime.WarnDefinitions.*;
import static me.bechberger.ebpf.runtime.WatchDefinitions.*;
import static me.bechberger.ebpf.runtime.WatchdogDefinitions.*;
import static me.bechberger.ebpf.runtime.WbDefinitions.*;
import static me.bechberger.ebpf.runtime.WbtDefinitions.*;
import static me.bechberger.ebpf.runtime.WiphyDefinitions.*;
import static me.bechberger.ebpf.runtime.WirelessDefinitions.*;
import static me.bechberger.ebpf.runtime.Wm831xDefinitions.*;
import static me.bechberger.ebpf.runtime.Wm8350Definitions.*;
import static me.bechberger.ebpf.runtime.WorkqueueDefinitions.*;
import static me.bechberger.ebpf.runtime.WpDefinitions.*;
import static me.bechberger.ebpf.runtime.WqDefinitions.*;
import static me.bechberger.ebpf.runtime.WriteDefinitions.*;
import static me.bechberger.ebpf.runtime.WritebackDefinitions.*;
import static me.bechberger.ebpf.runtime.WwDefinitions.*;
import static me.bechberger.ebpf.runtime.X2apicDefinitions.*;
import static me.bechberger.ebpf.runtime.X509Definitions.*;
import static me.bechberger.ebpf.runtime.X64Definitions.*;
import static me.bechberger.ebpf.runtime.X86Definitions.*;
import static me.bechberger.ebpf.runtime.XaDefinitions.*;
import static me.bechberger.ebpf.runtime.XasDefinitions.*;
import static me.bechberger.ebpf.runtime.XattrDefinitions.*;
import static me.bechberger.ebpf.runtime.XbcDefinitions.*;
import static me.bechberger.ebpf.runtime.XdbcDefinitions.*;
import static me.bechberger.ebpf.runtime.XdpDefinitions.*;
import static me.bechberger.ebpf.runtime.XenDefinitions.*;
import static me.bechberger.ebpf.runtime.XenbusDefinitions.*;
import static me.bechberger.ebpf.runtime.XennetDefinitions.*;
import static me.bechberger.ebpf.runtime.XenpfDefinitions.*;
import static me.bechberger.ebpf.runtime.Xfrm4Definitions.*;
import static me.bechberger.ebpf.runtime.Xfrm6Definitions.*;
import static me.bechberger.ebpf.runtime.XfrmDefinitions.*;
import static me.bechberger.ebpf.runtime.XhciDefinitions.*;
import static me.bechberger.ebpf.runtime.XpDefinitions.*;
import static me.bechberger.ebpf.runtime.XsDefinitions.*;
import static me.bechberger.ebpf.runtime.XskDefinitions.*;
import static me.bechberger.ebpf.runtime.XtsDefinitions.*;
import static me.bechberger.ebpf.runtime.XzDefinitions.*;
import static me.bechberger.ebpf.runtime.ZapDefinitions.*;
import static me.bechberger.ebpf.runtime.ZlibDefinitions.*;
import static me.bechberger.ebpf.runtime.ZoneDefinitions.*;
import static me.bechberger.ebpf.runtime.ZpoolDefinitions.*;
import static me.bechberger.ebpf.runtime.ZsDefinitions.*;
import static me.bechberger.ebpf.runtime.ZstdDefinitions.*;
import static me.bechberger.ebpf.runtime.ZswapDefinitions.*;
import static me.bechberger.ebpf.runtime.misc.*;
import static me.bechberger.ebpf.runtime.runtime.*;

/**
 * Generated class for BPF runtime types that start with netdev
 */
@java.lang.SuppressWarnings("unused")
public final class NetdevDefinitions {
  @NotUsableInJava
  @BuiltinBPFFunction
  public static int ____netdev_has_upper_dev(Ptr<net_device> upper_dev,
      Ptr<netdev_nested_priv> priv) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int __netdev_adjacent_dev_insert(Ptr<net_device> dev, Ptr<net_device> adj_dev,
      Ptr<list_head> dev_list, Ptr<?> _private, boolean master) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __netdev_adjacent_dev_set(Ptr<net_device> upper_dev, Ptr<net_device> lower_dev,
      boolean val) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static Ptr<?> __netdev_alloc_frag_align(@Unsigned int fragsz, @Unsigned int align_mask) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static Ptr<sk_buff> __netdev_alloc_skb(Ptr<net_device> dev, @Unsigned int len,
      @Unsigned @OriginalName("gfp_t") int gfp_mask) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static boolean __netdev_has_upper_dev(Ptr<net_device> dev, Ptr<net_device> upper_dev) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static char __netdev_lower_depth(Ptr<net_device> dev) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __netdev_nl_sock_priv_destroy(Ptr<?> priv) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __netdev_nl_sock_priv_init(Ptr<?> priv) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __netdev_notify_peers(Ptr<net_device> dev) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("__netdev_printk((const u8*)$arg1, (const struct net_device*)$arg2, $arg3)")
  public static void __netdev_printk(String level, Ptr<net_device> dev, Ptr<va_format> vaf) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static Ptr<net_device> __netdev_put_lock(Ptr<net_device> dev, Ptr<net> net) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static Ptr<net_device> __netdev_put_lock_ops_compat(Ptr<net_device> dev, Ptr<net> net) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static boolean __netdev_tx_sent_queue(Ptr<netdev_queue> dev_queue, @Unsigned int bytes,
      boolean xmit_more) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int __netdev_update_features(Ptr<net_device> dev) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int __netdev_update_lower_level(Ptr<net_device> dev, Ptr<netdev_nested_priv> priv) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int __netdev_update_upper_level(Ptr<net_device> dev,
      Ptr<netdev_nested_priv> __unused) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static char __netdev_upper_depth(Ptr<net_device> dev) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int __netdev_upper_dev_link(Ptr<net_device> dev, Ptr<net_device> upper_dev,
      boolean master, Ptr<?> upper_priv, Ptr<?> upper_info, Ptr<netdev_nested_priv> priv,
      Ptr<netlink_ext_ack> extack) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __netdev_upper_dev_unlink(Ptr<net_device> dev, Ptr<net_device> upper_dev,
      Ptr<netdev_nested_priv> priv) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("__netdev_walk_all_upper_dev($arg1, (int (*)(struct net_device*, struct netdev_nested_priv*))$arg2, $arg3)")
  public static int __netdev_walk_all_upper_dev(Ptr<net_device> dev, Ptr<?> fn,
      Ptr<netdev_nested_priv> priv) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void netdev_adjacent_change_abort(Ptr<net_device> old_dev, Ptr<net_device> new_dev,
      Ptr<net_device> dev) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void netdev_adjacent_change_commit(Ptr<net_device> old_dev, Ptr<net_device> new_dev,
      Ptr<net_device> dev) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int netdev_adjacent_change_prepare(Ptr<net_device> old_dev, Ptr<net_device> new_dev,
      Ptr<net_device> dev, Ptr<netlink_ext_ack> extack) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static Ptr<?> netdev_adjacent_get_private(Ptr<list_head> adj_list) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void netdev_adjacent_rename_links(Ptr<net_device> dev, String oldname) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("netdev_alert((const struct net_device*)$arg1, (const u8*)$arg2, $arg3_)")
  public static void netdev_alert(Ptr<net_device> dev, String fmt, java.lang.Object... param2) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int netdev_bind_sb_channel_queue(Ptr<net_device> dev, Ptr<net_device> sb_dev,
      char tc, @Unsigned short count, @Unsigned short offset) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("netdev_bits($arg1, $arg2, (const void*)$arg3, $arg4, (const u8*)$arg5)")
  public static String netdev_bits(String buf, String end, Ptr<?> addr, printf_spec spec,
      String fmt) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void netdev_bonding_info_change(Ptr<net_device> dev,
      Ptr<netdev_bonding_info> bonding_info) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void netdev_change_features(Ptr<net_device> dev) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("netdev_change_owner($arg1, (const struct net*)$arg2, (const struct net*)$arg3)")
  public static int netdev_change_owner(Ptr<net_device> ndev, Ptr<net> net_old, Ptr<net> net_new) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void netdev_change_proto_down_reason_locked(Ptr<net_device> dev,
      @Unsigned long mask, @Unsigned int value) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("netdev_class_create_file_ns((const struct class_attribute*)$arg1, (const void*)$arg2)")
  public static int netdev_class_create_file_ns(Ptr<class_attribute> class_attr, Ptr<?> ns) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("netdev_class_remove_file_ns((const struct class_attribute*)$arg1, (const void*)$arg2)")
  public static void netdev_class_remove_file_ns(Ptr<class_attribute> class_attr, Ptr<?> ns) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("((const u8*)netdev_cmd_to_name($arg1))")
  public static String netdev_cmd_to_name(netdev_cmd cmd) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void netdev_copy_name(Ptr<net_device> dev, String name) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static Ptr<netdev_queue> netdev_core_pick_tx(Ptr<net_device> dev, Ptr<sk_buff> skb,
      Ptr<net_device> sb_dev) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void netdev_core_stats_inc(Ptr<net_device> dev, @Unsigned int offset) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static Ptr<hlist_head> netdev_create_hash() {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("netdev_crit((const struct net_device*)$arg1, (const u8*)$arg2, $arg3_)")
  public static void netdev_crit(Ptr<net_device> dev, String fmt, java.lang.Object... param2) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int netdev_devres_match(Ptr<device> dev, Ptr<?> _this, Ptr<?> match_data) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int netdev_do_alloc_pcpu_stats(Ptr<net_device> dev) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("((const u8*)netdev_drivername((const struct net_device*)$arg1))")
  public static String netdev_drivername(Ptr<net_device> dev) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("netdev_emerg((const struct net_device*)$arg1, (const u8*)$arg2, $arg3_)")
  public static void netdev_emerg(Ptr<net_device> dev, String fmt, java.lang.Object... param2) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("netdev_err((const struct net_device*)$arg1, (const u8*)$arg2, $arg3_)")
  public static void netdev_err(Ptr<net_device> dev, String fmt, java.lang.Object... param2) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void netdev_exit(Ptr<net> net) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void netdev_features_change(Ptr<net_device> dev) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static @Unsigned @OriginalName("netdev_features_t") long netdev_fix_features(
      Ptr<net_device> dev, @Unsigned @OriginalName("netdev_features_t") long features) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("netdev_for_each_tx_queue($arg1, (void (*)(struct net_device*, struct netdev_queue*, void*))$arg2, $arg3)")
  public static void netdev_for_each_tx_queue(Ptr<net_device> dev, Ptr<?> f, Ptr<?> arg) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void netdev_genl_dev_notify(Ptr<net_device> netdev, int cmd) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int netdev_genl_init() {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int netdev_genl_netdevice_event(Ptr<notifier_block> nb, @Unsigned long event,
      Ptr<?> ptr) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static Ptr<net_device> netdev_get_by_flags_rcu(Ptr<net> net,
      Ptr<@OriginalName("netdevice_tracker") lockdep_map_p> tracker, @Unsigned short if_flags,
      @Unsigned short mask) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static Ptr<net_device> netdev_get_by_index(Ptr<net> net, int ifindex,
      Ptr<@OriginalName("netdevice_tracker") lockdep_map_p> tracker,
      @Unsigned @OriginalName("gfp_t") int gfp) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static Ptr<net_device> netdev_get_by_index_lock(Ptr<net> net, int ifindex) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static Ptr<net_device> netdev_get_by_index_lock_ops_compat(Ptr<net> net, int ifindex) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("netdev_get_by_name($arg1, (const u8*)$arg2, $arg3, $arg4)")
  public static Ptr<net_device> netdev_get_by_name(Ptr<net> net, String name,
      Ptr<@OriginalName("netdevice_tracker") lockdep_map_p> tracker,
      @Unsigned @OriginalName("gfp_t") int gfp) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int netdev_get_name(Ptr<net> net, String name, int ifindex) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static Ptr<net_device> netdev_get_xmit_slave(Ptr<net_device> dev, Ptr<sk_buff> skb,
      boolean all_slaves) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static boolean netdev_has_any_upper_dev(Ptr<net_device> dev) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static boolean netdev_has_upper_dev(Ptr<net_device> dev, Ptr<net_device> upper_dev) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static boolean netdev_has_upper_dev_all_rcu(Ptr<net_device> dev,
      Ptr<net_device> upper_dev) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("netdev_hw_stats64_add($arg1, (const struct rtnl_hw_stats64*)$arg2)")
  public static void netdev_hw_stats64_add(Ptr<rtnl_hw_stats64> dest, Ptr<rtnl_hw_stats64> src) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static @Unsigned @OriginalName("netdev_features_t") long netdev_increment_features(
      @Unsigned @OriginalName("netdev_features_t") long all,
      @Unsigned @OriginalName("netdev_features_t") long one,
      @Unsigned @OriginalName("netdev_features_t") long mask) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("netdev_info((const struct net_device*)$arg1, (const u8*)$arg2, $arg3_)")
  public static void netdev_info(Ptr<net_device> dev, String fmt, java.lang.Object... param2) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int netdev_init(Ptr<net> net) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static boolean netdev_is_rx_handler_busy(Ptr<net_device> dev) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int netdev_kobject_init() {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static Ptr<?> netdev_lower_dev_get_private(Ptr<net_device> dev,
      Ptr<net_device> lower_dev) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static Ptr<?> netdev_lower_get_first_private_rcu(Ptr<net_device> dev) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static Ptr<?> netdev_lower_get_next(Ptr<net_device> dev, Ptr<Ptr<list_head>> iter) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static Ptr<?> netdev_lower_get_next_private(Ptr<net_device> dev,
      Ptr<Ptr<list_head>> iter) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static Ptr<?> netdev_lower_get_next_private_rcu(Ptr<net_device> dev,
      Ptr<Ptr<list_head>> iter) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void netdev_lower_state_changed(Ptr<net_device> lower_dev,
      Ptr<?> lower_state_info) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static Ptr<net_device> netdev_master_upper_dev_get(Ptr<net_device> dev) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static Ptr<net_device> netdev_master_upper_dev_get_rcu(Ptr<net_device> dev) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int netdev_master_upper_dev_link(Ptr<net_device> dev, Ptr<net_device> upper_dev,
      Ptr<?> upper_priv, Ptr<?> upper_info, Ptr<netlink_ext_ack> extack) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("((const u8*)netdev_name((const struct net_device*)$arg1))")
  public static String netdev_name(Ptr<net_device> dev) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("netdev_name_in_use($arg1, (const u8*)$arg2)")
  public static boolean netdev_name_in_use(Ptr<net> net, String name) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("netdev_name_node_alt_create($arg1, (const u8*)$arg2)")
  public static int netdev_name_node_alt_create(Ptr<net_device> dev, String name) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("netdev_name_node_alt_destroy($arg1, (const u8*)$arg2)")
  public static int netdev_name_node_alt_destroy(Ptr<net_device> dev, String name) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void netdev_name_node_alt_free(Ptr<callback_head> head) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("netdev_name_node_lookup($arg1, (const u8*)$arg2)")
  public static Ptr<netdev_name_node> netdev_name_node_lookup(Ptr<net> net, String name) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static Ptr<napi_struct> netdev_napi_by_id_lock(Ptr<net> net, @Unsigned int napi_id) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static Ptr<net_device> netdev_next_lower_dev_rcu(Ptr<net_device> dev,
      Ptr<Ptr<list_head>> iter) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int netdev_nl_bind_rx_doit(Ptr<sk_buff> skb, Ptr<genl_info> info) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int netdev_nl_bind_tx_doit(Ptr<sk_buff> skb, Ptr<genl_info> info) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("netdev_nl_dev_fill($arg1, $arg2, (const struct genl_info*)$arg3)")
  public static int netdev_nl_dev_fill(Ptr<net_device> netdev, Ptr<sk_buff> rsp,
      Ptr<genl_info> info) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int netdev_nl_dev_get_doit(Ptr<sk_buff> skb, Ptr<genl_info> info) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int netdev_nl_dev_get_dumpit(Ptr<sk_buff> skb, Ptr<netlink_callback> cb) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("netdev_nl_napi_dump_one($arg1, $arg2, (const struct genl_info*)$arg3, $arg4)")
  public static int netdev_nl_napi_dump_one(Ptr<net_device> netdev, Ptr<sk_buff> rsp,
      Ptr<genl_info> info, Ptr<netdev_nl_dump_ctx> ctx) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("netdev_nl_napi_fill_one($arg1, $arg2, (const struct genl_info*)$arg3)")
  public static int netdev_nl_napi_fill_one(Ptr<sk_buff> rsp, Ptr<napi_struct> napi,
      Ptr<genl_info> info) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int netdev_nl_napi_get_doit(Ptr<sk_buff> skb, Ptr<genl_info> info) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int netdev_nl_napi_get_dumpit(Ptr<sk_buff> skb, Ptr<netlink_callback> cb) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int netdev_nl_napi_set_doit(Ptr<sk_buff> skb, Ptr<genl_info> info) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("netdev_nl_page_pool_event((const struct page_pool*)$arg1, $arg2)")
  public static void netdev_nl_page_pool_event(Ptr<page_pool> pool, @Unsigned int cmd) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int netdev_nl_page_pool_get_do(Ptr<genl_info> info, @Unsigned int id,
      @OriginalName("pp_nl_fill_cb") Ptr<?> fill) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int netdev_nl_page_pool_get_doit(Ptr<sk_buff> skb, Ptr<genl_info> info) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int netdev_nl_page_pool_get_dump(Ptr<sk_buff> skb, Ptr<netlink_callback> cb,
      @OriginalName("pp_nl_fill_cb") Ptr<?> fill) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int netdev_nl_page_pool_get_dumpit(Ptr<sk_buff> skb, Ptr<netlink_callback> cb) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int netdev_nl_page_pool_stats_get_doit(Ptr<sk_buff> skb, Ptr<genl_info> info) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int netdev_nl_page_pool_stats_get_dumpit(Ptr<sk_buff> skb,
      Ptr<netlink_callback> cb) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("netdev_nl_qstats_get_dump_one($arg1, $arg2, $arg3, (const struct genl_info*)$arg4, $arg5)")
  public static int netdev_nl_qstats_get_dump_one(Ptr<net_device> netdev, @Unsigned int scope,
      Ptr<sk_buff> skb, Ptr<genl_info> info, Ptr<netdev_nl_dump_ctx> ctx) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int netdev_nl_qstats_get_dumpit(Ptr<sk_buff> skb, Ptr<netlink_callback> cb) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("netdev_nl_queue_dump_one($arg1, $arg2, (const struct genl_info*)$arg3, $arg4)")
  public static int netdev_nl_queue_dump_one(Ptr<net_device> netdev, Ptr<sk_buff> rsp,
      Ptr<genl_info> info, Ptr<netdev_nl_dump_ctx> ctx) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("netdev_nl_queue_fill_one($arg1, $arg2, $arg3, $arg4, (const struct genl_info*)$arg5)")
  public static int netdev_nl_queue_fill_one(Ptr<sk_buff> rsp, Ptr<net_device> netdev,
      @Unsigned int q_idx, @Unsigned int q_type, Ptr<genl_info> info) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int netdev_nl_queue_get_doit(Ptr<sk_buff> skb, Ptr<genl_info> info) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int netdev_nl_queue_get_dumpit(Ptr<sk_buff> skb, Ptr<netlink_callback> cb) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void netdev_nl_sock_priv_destroy(Ptr<netdev_nl_sock> priv) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void netdev_nl_sock_priv_init(Ptr<netdev_nl_sock> priv) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("netdev_nl_stats_by_netdev($arg1, $arg2, (const struct genl_info*)$arg3)")
  public static int netdev_nl_stats_by_netdev(Ptr<net_device> netdev, Ptr<sk_buff> rsp,
      Ptr<genl_info> info) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("netdev_nl_stats_queue($arg1, $arg2, $arg3, $arg4, (const struct genl_info*)$arg5)")
  public static int netdev_nl_stats_queue(Ptr<net_device> netdev, Ptr<sk_buff> rsp,
      @Unsigned int q_type, int i, Ptr<genl_info> info) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int netdev_nl_stats_write_rx(Ptr<sk_buff> rsp, Ptr<netdev_queue_stats_rx> rx) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int netdev_nl_stats_write_tx(Ptr<sk_buff> rsp, Ptr<netdev_queue_stats_tx> tx) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("netdev_notice((const struct net_device*)$arg1, (const u8*)$arg2, $arg3_)")
  public static void netdev_notice(Ptr<net_device> dev, String fmt, java.lang.Object... param2) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void netdev_notify_peers(Ptr<net_device> dev) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int netdev_offload_xstats_disable(Ptr<net_device> dev,
      netdev_offload_xstats_type type) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int netdev_offload_xstats_enable(Ptr<net_device> dev,
      netdev_offload_xstats_type type, Ptr<netlink_ext_ack> extack) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("netdev_offload_xstats_enabled((const struct net_device*)$arg1, $arg2)")
  public static boolean netdev_offload_xstats_enabled(Ptr<net_device> dev,
      netdev_offload_xstats_type type) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int netdev_offload_xstats_get(Ptr<net_device> dev, netdev_offload_xstats_type type,
      Ptr<rtnl_hw_stats64> p_stats, Ptr<java.lang. @OriginalName("bool") Boolean> p_used,
      Ptr<netlink_ext_ack> extack) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int netdev_offload_xstats_get_stats(Ptr<net_device> dev,
      netdev_offload_xstats_type type, Ptr<rtnl_hw_stats64> p_stats,
      Ptr<java.lang. @OriginalName("bool") Boolean> p_used, Ptr<netlink_ext_ack> extack) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("netdev_offload_xstats_push_delta($arg1, $arg2, (const struct rtnl_hw_stats64*)$arg3)")
  public static void netdev_offload_xstats_push_delta(Ptr<net_device> dev,
      netdev_offload_xstats_type type, Ptr<rtnl_hw_stats64> p_stats) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("netdev_offload_xstats_report_delta($arg1, (const struct rtnl_hw_stats64*)$arg2)")
  public static void netdev_offload_xstats_report_delta(
      Ptr<netdev_notifier_offload_xstats_rd> report_delta, Ptr<rtnl_hw_stats64> stats) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void netdev_offload_xstats_report_used(
      Ptr<netdev_notifier_offload_xstats_ru> report_used) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("netdev_ops_assert_locked((const struct net_device*)$arg1)")
  public static void netdev_ops_assert_locked(Ptr<net_device> dev) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static @Unsigned @OriginalName("umode_t") short netdev_phys_is_visible(Ptr<kobject> kobj,
      Ptr<attribute> attr, int index) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static @Unsigned short netdev_pick_tx(Ptr<net_device> dev, Ptr<sk_buff> skb,
      Ptr<net_device> sb_dev) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static boolean netdev_port_same_parent_id(Ptr<net_device> a, Ptr<net_device> b) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("netdev_printk((const u8*)$arg1, (const struct net_device*)$arg2, (const u8*)$arg3, $arg4_)")
  public static void netdev_printk(String level, Ptr<net_device> dev, String format,
      java.lang.Object... param3) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static @OriginalName("ssize_t") long netdev_queue_attr_show(Ptr<kobject> kobj,
      Ptr<attribute> attr, String buf) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("netdev_queue_attr_store($arg1, $arg2, (const u8*)$arg3, $arg4)")
  public static @OriginalName("ssize_t") long netdev_queue_attr_store(Ptr<kobject> kobj,
      Ptr<attribute> attr, String buf, @Unsigned long count) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("netdev_queue_get_ownership((const struct kobject*)$arg1, $arg2, $arg3)")
  public static void netdev_queue_get_ownership(Ptr<kobject> kobj, Ptr<kuid_t> uid,
      Ptr<kgid_t> gid) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("((const void*)netdev_queue_namespace((const struct kobject*)$arg1))")
  public static Ptr<?> netdev_queue_namespace(Ptr<kobject> kobj) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void netdev_queue_release(Ptr<kobject> kobj) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int netdev_queue_update_kobjects(Ptr<net_device> dev, int old_num, int new_num) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("netdev_refcnt_read((const struct net_device*)$arg1)")
  public static int netdev_refcnt_read(Ptr<net_device> dev) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int netdev_register_kobject(Ptr<net_device> ndev) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void netdev_release(Ptr<device> d) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void netdev_reset_tc(Ptr<net_device> dev) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void netdev_rss_key_fill(Ptr<?> buffer, @Unsigned long len) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void netdev_run_todo() {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void netdev_rx_csum_fault(Ptr<net_device> dev, Ptr<sk_buff> skb) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int netdev_rx_handler_register(Ptr<net_device> dev, Ptr<?> rx_handler,
      Ptr<?> rx_handler_data) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void netdev_rx_handler_unregister(Ptr<net_device> dev) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int netdev_rx_queue_restart(Ptr<net_device> dev, @Unsigned int rxq_idx) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int netdev_rx_queue_set_rps_mask(Ptr<netdev_rx_queue> queue,
      @OriginalName("cpumask_var_t") Ptr<cpumask> mask) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("netdev_set_default_ethtool_ops($arg1, (const struct ethtool_ops*)$arg2)")
  public static void netdev_set_default_ethtool_ops(Ptr<net_device> dev, Ptr<ethtool_ops> ops) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int netdev_set_num_tc(Ptr<net_device> dev, char num_tc) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int netdev_set_sb_channel(Ptr<net_device> dev, @Unsigned short channel) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int netdev_set_tc_queue(Ptr<net_device> dev, char tc, @Unsigned short count,
      @Unsigned short offset) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static Ptr<net_device> netdev_sk_get_lowest_dev(Ptr<net_device> dev, Ptr<sock> sk) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void netdev_stat_queue_sum(Ptr<net_device> netdev, int rx_start, int rx_end,
      Ptr<netdev_queue_stats_rx> rx_sum, int tx_start, int tx_end,
      Ptr<netdev_queue_stats_tx> tx_sum) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void netdev_state_change(Ptr<net_device> dev) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("netdev_stats_to_stats64($arg1, (const struct net_device_stats*)$arg2)")
  public static void netdev_stats_to_stats64(Ptr<rtnl_link_stats64> stats64,
      Ptr<net_device_stats> netdev_stats) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("netdev_store($arg1, $arg2, (const u8*)$arg3, $arg4, (int (*)(struct net_device*, long unsigned int))$arg5)")
  public static @OriginalName("ssize_t") long netdev_store(Ptr<device> dev,
      Ptr<device_attribute> attr, String buf, @Unsigned long len, Ptr<?> set) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void netdev_sw_irq_coalesce_default_on(Ptr<net_device> dev) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void netdev_sync_lower_features(Ptr<net_device> upper, Ptr<net_device> lower,
      @Unsigned @OriginalName("netdev_features_t") long features) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int netdev_txq_to_tc(Ptr<net_device> dev, @Unsigned int txq) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("netdev_uevent((const struct device*)$arg1, $arg2)")
  public static int netdev_uevent(Ptr<device> d, Ptr<kobj_uevent_env> env) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void netdev_unbind_sb_channel(Ptr<net_device> dev, Ptr<net_device> sb_dev) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void netdev_unregister_kobject(Ptr<net_device> ndev) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void netdev_update_features(Ptr<net_device> dev) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int netdev_upper_dev_link(Ptr<net_device> dev, Ptr<net_device> upper_dev,
      Ptr<netlink_ext_ack> extack) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void netdev_upper_dev_unlink(Ptr<net_device> dev, Ptr<net_device> upper_dev) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static Ptr<net_device> netdev_upper_get_next_dev_rcu(Ptr<net_device> dev,
      Ptr<Ptr<list_head>> iter) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static Ptr<net_device> netdev_wait_allrefs_any(Ptr<list_head> list) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("netdev_walk_all_lower_dev($arg1, (int (*)(struct net_device*, struct netdev_nested_priv*))$arg2, $arg3)")
  public static int netdev_walk_all_lower_dev(Ptr<net_device> dev, Ptr<?> fn,
      Ptr<netdev_nested_priv> priv) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("netdev_walk_all_lower_dev_rcu($arg1, (int (*)(struct net_device*, struct netdev_nested_priv*))$arg2, $arg3)")
  public static int netdev_walk_all_lower_dev_rcu(Ptr<net_device> dev, Ptr<?> fn,
      Ptr<netdev_nested_priv> priv) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("netdev_walk_all_upper_dev_rcu($arg1, (int (*)(struct net_device*, struct netdev_nested_priv*))$arg2, $arg3)")
  public static int netdev_walk_all_upper_dev_rcu(Ptr<net_device> dev, Ptr<?> fn,
      Ptr<netdev_nested_priv> priv) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("netdev_warn((const struct net_device*)$arg1, (const u8*)$arg2, $arg3_)")
  public static void netdev_warn(Ptr<net_device> dev, String fmt, java.lang.Object... param2) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void netdev_watchdog_up(Ptr<net_device> dev) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static Ptr<net_device> netdev_xa_find_lock(Ptr<net> net, Ptr<net_device> dev,
      Ptr<java.lang. @Unsigned Long> index) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static Ptr<net_device> netdev_xa_find_lock_ops_compat(Ptr<net> net, Ptr<net_device> dev,
      Ptr<java.lang. @Unsigned Long> index) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void netdev_xmit_skip_txqueue(boolean skip) {
    throw new MethodIsBPFRelatedFunction();
  }

  @Type(
      noCCodeGeneration = true,
      cType = "enum netdev_tx"
  )
  public enum netdev_tx implements Enum<netdev_tx>, TypedEnum<netdev_tx, java.lang.Integer> {
    /**
     * {@code __NETDEV_TX_MIN = -2147483648}
     */
    @EnumMember(
        value = -2147483648L,
        name = "__NETDEV_TX_MIN"
    )
    __NETDEV_TX_MIN,

    /**
     * {@code NETDEV_TX_OK = 0}
     */
    @EnumMember(
        value = 0L,
        name = "NETDEV_TX_OK"
    )
    NETDEV_TX_OK,

    /**
     * {@code NETDEV_TX_BUSY = 16}
     */
    @EnumMember(
        value = 16L,
        name = "NETDEV_TX_BUSY"
    )
    NETDEV_TX_BUSY
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct netdev_hw_addr_list"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class netdev_hw_addr_list extends Struct {
    public list_head list;

    public int count;

    public rb_root tree;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct netdev_queue"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class netdev_queue extends Struct {
    public Ptr<net_device> dev;

    public @OriginalName("netdevice_tracker") lockdep_map_p dev_tracker;

    public Ptr<Qdisc> qdisc;

    public Ptr<Qdisc> qdisc_sleeping;

    public kobject kobj;

    public Ptr<Ptr<attribute_group>> groups;

    public @Unsigned long tx_maxrate;

    public @OriginalName("atomic_long_t") atomic64_t trans_timeout;

    public Ptr<net_device> sb_dev;

    public Ptr<xsk_buff_pool> pool;

    public dql dql;

    public @OriginalName("spinlock_t") spinlock _xmit_lock;

    public int xmit_lock_owner;

    public @Unsigned long trans_start;

    public @Unsigned long state;

    public Ptr<napi_struct> napi;

    public int numa_node;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct netdev_tc_txq"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class netdev_tc_txq extends Struct {
    public @Unsigned short count;

    public @Unsigned short offset;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct netdev_fcoe_hbainfo"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class netdev_fcoe_hbainfo extends Struct {
    public char @Size(64) [] manufacturer;

    public char @Size(64) [] serial_number;

    public char @Size(64) [] hardware_version;

    public char @Size(64) [] driver_version;

    public char @Size(64) [] optionrom_version;

    public char @Size(64) [] firmware_version;

    public char @Size(256) [] model;

    public char @Size(256) [] model_description;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct netdev_phys_item_id"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class netdev_phys_item_id extends Struct {
    public char @Size(32) [] id;

    public char id_len;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct netdev_bpf"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class netdev_bpf extends Struct {
    public bpf_netdev_command command;

    @InlineUnion(3506)
    public anon_member_of_anon_member_of_netdev_bpf anon1$0;

    @InlineUnion(3506)
    public anon_member_of_anon_member_of_netdev_bpf anon1$1;

    @InlineUnion(3506)
    public xsk_of_anon_member_of_netdev_bpf xsk;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "enum netdev_ml_priv_type"
  )
  public enum netdev_ml_priv_type implements Enum<netdev_ml_priv_type>, TypedEnum<netdev_ml_priv_type, java.lang. @Unsigned Integer> {
    /**
     * {@code ML_PRIV_NONE = 0}
     */
    @EnumMember(
        value = 0L,
        name = "ML_PRIV_NONE"
    )
    ML_PRIV_NONE,

    /**
     * {@code ML_PRIV_CAN = 1}
     */
    @EnumMember(
        value = 1L,
        name = "ML_PRIV_CAN"
    )
    ML_PRIV_CAN
  }

  @Type(
      noCCodeGeneration = true,
      cType = "enum netdev_stat_type"
  )
  public enum netdev_stat_type implements Enum<netdev_stat_type>, TypedEnum<netdev_stat_type, java.lang. @Unsigned Integer> {
    /**
     * {@code NETDEV_PCPU_STAT_NONE = 0}
     */
    @EnumMember(
        value = 0L,
        name = "NETDEV_PCPU_STAT_NONE"
    )
    NETDEV_PCPU_STAT_NONE,

    /**
     * {@code NETDEV_PCPU_STAT_LSTATS = 1}
     */
    @EnumMember(
        value = 1L,
        name = "NETDEV_PCPU_STAT_LSTATS"
    )
    NETDEV_PCPU_STAT_LSTATS,

    /**
     * {@code NETDEV_PCPU_STAT_TSTATS = 2}
     */
    @EnumMember(
        value = 2L,
        name = "NETDEV_PCPU_STAT_TSTATS"
    )
    NETDEV_PCPU_STAT_TSTATS,

    /**
     * {@code NETDEV_PCPU_STAT_DSTATS = 3}
     */
    @EnumMember(
        value = 3L,
        name = "NETDEV_PCPU_STAT_DSTATS"
    )
    NETDEV_PCPU_STAT_DSTATS
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct netdev_stat_ops"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class netdev_stat_ops extends Struct {
    public Ptr<?> get_queue_stats_rx;

    public Ptr<?> get_queue_stats_tx;

    public Ptr<?> get_base_stats;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct netdev_queue_mgmt_ops"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class netdev_queue_mgmt_ops extends Struct {
    public @Unsigned long ndo_queue_mem_size;

    public Ptr<?> ndo_queue_mem_alloc;

    public Ptr<?> ndo_queue_mem_free;

    public Ptr<?> ndo_queue_start;

    public Ptr<?> ndo_queue_stop;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "enum netdev_xdp_act"
  )
  public enum netdev_xdp_act implements Enum<netdev_xdp_act>, TypedEnum<netdev_xdp_act, java.lang. @Unsigned Integer> {
    /**
     * {@code NETDEV_XDP_ACT_BASIC = 1}
     */
    @EnumMember(
        value = 1L,
        name = "NETDEV_XDP_ACT_BASIC"
    )
    NETDEV_XDP_ACT_BASIC,

    /**
     * {@code NETDEV_XDP_ACT_REDIRECT = 2}
     */
    @EnumMember(
        value = 2L,
        name = "NETDEV_XDP_ACT_REDIRECT"
    )
    NETDEV_XDP_ACT_REDIRECT,

    /**
     * {@code NETDEV_XDP_ACT_NDO_XMIT = 4}
     */
    @EnumMember(
        value = 4L,
        name = "NETDEV_XDP_ACT_NDO_XMIT"
    )
    NETDEV_XDP_ACT_NDO_XMIT,

    /**
     * {@code NETDEV_XDP_ACT_XSK_ZEROCOPY = 8}
     */
    @EnumMember(
        value = 8L,
        name = "NETDEV_XDP_ACT_XSK_ZEROCOPY"
    )
    NETDEV_XDP_ACT_XSK_ZEROCOPY,

    /**
     * {@code NETDEV_XDP_ACT_HW_OFFLOAD = 16}
     */
    @EnumMember(
        value = 16L,
        name = "NETDEV_XDP_ACT_HW_OFFLOAD"
    )
    NETDEV_XDP_ACT_HW_OFFLOAD,

    /**
     * {@code NETDEV_XDP_ACT_RX_SG = 32}
     */
    @EnumMember(
        value = 32L,
        name = "NETDEV_XDP_ACT_RX_SG"
    )
    NETDEV_XDP_ACT_RX_SG,

    /**
     * {@code NETDEV_XDP_ACT_NDO_XMIT_SG = 64}
     */
    @EnumMember(
        value = 64L,
        name = "NETDEV_XDP_ACT_NDO_XMIT_SG"
    )
    NETDEV_XDP_ACT_NDO_XMIT_SG,

    /**
     * {@code NETDEV_XDP_ACT_MASK = 127}
     */
    @EnumMember(
        value = 127L,
        name = "NETDEV_XDP_ACT_MASK"
    )
    NETDEV_XDP_ACT_MASK
  }

  @Type(
      noCCodeGeneration = true,
      cType = "enum netdev_priv_flags"
  )
  public enum netdev_priv_flags implements Enum<netdev_priv_flags>, TypedEnum<netdev_priv_flags, java.lang. @Unsigned Integer> {
    /**
     * {@code IFF_802_1Q_VLAN = 1}
     */
    @EnumMember(
        value = 1L,
        name = "IFF_802_1Q_VLAN"
    )
    IFF_802_1Q_VLAN,

    /**
     * {@code IFF_EBRIDGE = 2}
     */
    @EnumMember(
        value = 2L,
        name = "IFF_EBRIDGE"
    )
    IFF_EBRIDGE,

    /**
     * {@code IFF_BONDING = 4}
     */
    @EnumMember(
        value = 4L,
        name = "IFF_BONDING"
    )
    IFF_BONDING,

    /**
     * {@code IFF_ISATAP = 8}
     */
    @EnumMember(
        value = 8L,
        name = "IFF_ISATAP"
    )
    IFF_ISATAP,

    /**
     * {@code IFF_WAN_HDLC = 16}
     */
    @EnumMember(
        value = 16L,
        name = "IFF_WAN_HDLC"
    )
    IFF_WAN_HDLC,

    /**
     * {@code IFF_XMIT_DST_RELEASE = 32}
     */
    @EnumMember(
        value = 32L,
        name = "IFF_XMIT_DST_RELEASE"
    )
    IFF_XMIT_DST_RELEASE,

    /**
     * {@code IFF_DONT_BRIDGE = 64}
     */
    @EnumMember(
        value = 64L,
        name = "IFF_DONT_BRIDGE"
    )
    IFF_DONT_BRIDGE,

    /**
     * {@code IFF_DISABLE_NETPOLL = 128}
     */
    @EnumMember(
        value = 128L,
        name = "IFF_DISABLE_NETPOLL"
    )
    IFF_DISABLE_NETPOLL,

    /**
     * {@code IFF_MACVLAN_PORT = 256}
     */
    @EnumMember(
        value = 256L,
        name = "IFF_MACVLAN_PORT"
    )
    IFF_MACVLAN_PORT,

    /**
     * {@code IFF_BRIDGE_PORT = 512}
     */
    @EnumMember(
        value = 512L,
        name = "IFF_BRIDGE_PORT"
    )
    IFF_BRIDGE_PORT,

    /**
     * {@code IFF_OVS_DATAPATH = 1024}
     */
    @EnumMember(
        value = 1024L,
        name = "IFF_OVS_DATAPATH"
    )
    IFF_OVS_DATAPATH,

    /**
     * {@code IFF_TX_SKB_SHARING = 2048}
     */
    @EnumMember(
        value = 2048L,
        name = "IFF_TX_SKB_SHARING"
    )
    IFF_TX_SKB_SHARING,

    /**
     * {@code IFF_UNICAST_FLT = 4096}
     */
    @EnumMember(
        value = 4096L,
        name = "IFF_UNICAST_FLT"
    )
    IFF_UNICAST_FLT,

    /**
     * {@code IFF_TEAM_PORT = 8192}
     */
    @EnumMember(
        value = 8192L,
        name = "IFF_TEAM_PORT"
    )
    IFF_TEAM_PORT,

    /**
     * {@code IFF_SUPP_NOFCS = 16384}
     */
    @EnumMember(
        value = 16384L,
        name = "IFF_SUPP_NOFCS"
    )
    IFF_SUPP_NOFCS,

    /**
     * {@code IFF_LIVE_ADDR_CHANGE = 32768}
     */
    @EnumMember(
        value = 32768L,
        name = "IFF_LIVE_ADDR_CHANGE"
    )
    IFF_LIVE_ADDR_CHANGE,

    /**
     * {@code IFF_MACVLAN = 65536}
     */
    @EnumMember(
        value = 65536L,
        name = "IFF_MACVLAN"
    )
    IFF_MACVLAN,

    /**
     * {@code IFF_XMIT_DST_RELEASE_PERM = 131072}
     */
    @EnumMember(
        value = 131072L,
        name = "IFF_XMIT_DST_RELEASE_PERM"
    )
    IFF_XMIT_DST_RELEASE_PERM,

    /**
     * {@code IFF_L3MDEV_MASTER = 262144}
     */
    @EnumMember(
        value = 262144L,
        name = "IFF_L3MDEV_MASTER"
    )
    IFF_L3MDEV_MASTER,

    /**
     * {@code IFF_NO_QUEUE = 524288}
     */
    @EnumMember(
        value = 524288L,
        name = "IFF_NO_QUEUE"
    )
    IFF_NO_QUEUE,

    /**
     * {@code IFF_OPENVSWITCH = 1048576}
     */
    @EnumMember(
        value = 1048576L,
        name = "IFF_OPENVSWITCH"
    )
    IFF_OPENVSWITCH,

    /**
     * {@code IFF_L3MDEV_SLAVE = 2097152}
     */
    @EnumMember(
        value = 2097152L,
        name = "IFF_L3MDEV_SLAVE"
    )
    IFF_L3MDEV_SLAVE,

    /**
     * {@code IFF_TEAM = 4194304}
     */
    @EnumMember(
        value = 4194304L,
        name = "IFF_TEAM"
    )
    IFF_TEAM,

    /**
     * {@code IFF_RXFH_CONFIGURED = 8388608}
     */
    @EnumMember(
        value = 8388608L,
        name = "IFF_RXFH_CONFIGURED"
    )
    IFF_RXFH_CONFIGURED,

    /**
     * {@code IFF_PHONY_HEADROOM = 16777216}
     */
    @EnumMember(
        value = 16777216L,
        name = "IFF_PHONY_HEADROOM"
    )
    IFF_PHONY_HEADROOM,

    /**
     * {@code IFF_MACSEC = 33554432}
     */
    @EnumMember(
        value = 33554432L,
        name = "IFF_MACSEC"
    )
    IFF_MACSEC,

    /**
     * {@code IFF_NO_RX_HANDLER = 67108864}
     */
    @EnumMember(
        value = 67108864L,
        name = "IFF_NO_RX_HANDLER"
    )
    IFF_NO_RX_HANDLER,

    /**
     * {@code IFF_FAILOVER = 134217728}
     */
    @EnumMember(
        value = 134217728L,
        name = "IFF_FAILOVER"
    )
    IFF_FAILOVER,

    /**
     * {@code IFF_FAILOVER_SLAVE = 268435456}
     */
    @EnumMember(
        value = 268435456L,
        name = "IFF_FAILOVER_SLAVE"
    )
    IFF_FAILOVER_SLAVE,

    /**
     * {@code IFF_L3MDEV_RX_HANDLER = 536870912}
     */
    @EnumMember(
        value = 536870912L,
        name = "IFF_L3MDEV_RX_HANDLER"
    )
    IFF_L3MDEV_RX_HANDLER,

    /**
     * {@code IFF_NO_ADDRCONF = 1073741824}
     */
    @EnumMember(
        value = 1073741824L,
        name = "IFF_NO_ADDRCONF"
    )
    IFF_NO_ADDRCONF,

    /**
     * {@code IFF_TX_SKB_NO_LINEAR = -2147483648}
     */
    @EnumMember(
        value = -2147483648L,
        name = "IFF_TX_SKB_NO_LINEAR"
    )
    IFF_TX_SKB_NO_LINEAR
  }

  @Type(
      noCCodeGeneration = true,
      cType = "enum netdev_cmd"
  )
  public enum netdev_cmd implements Enum<netdev_cmd>, TypedEnum<netdev_cmd, java.lang. @Unsigned Integer> {
    /**
     * {@code NETDEV_UP = 1}
     */
    @EnumMember(
        value = 1L,
        name = "NETDEV_UP"
    )
    NETDEV_UP,

    /**
     * {@code NETDEV_DOWN = 2}
     */
    @EnumMember(
        value = 2L,
        name = "NETDEV_DOWN"
    )
    NETDEV_DOWN,

    /**
     * {@code NETDEV_REBOOT = 3}
     */
    @EnumMember(
        value = 3L,
        name = "NETDEV_REBOOT"
    )
    NETDEV_REBOOT,

    /**
     * {@code NETDEV_CHANGE = 4}
     */
    @EnumMember(
        value = 4L,
        name = "NETDEV_CHANGE"
    )
    NETDEV_CHANGE,

    /**
     * {@code NETDEV_REGISTER = 5}
     */
    @EnumMember(
        value = 5L,
        name = "NETDEV_REGISTER"
    )
    NETDEV_REGISTER,

    /**
     * {@code NETDEV_UNREGISTER = 6}
     */
    @EnumMember(
        value = 6L,
        name = "NETDEV_UNREGISTER"
    )
    NETDEV_UNREGISTER,

    /**
     * {@code NETDEV_CHANGEMTU = 7}
     */
    @EnumMember(
        value = 7L,
        name = "NETDEV_CHANGEMTU"
    )
    NETDEV_CHANGEMTU,

    /**
     * {@code NETDEV_CHANGEADDR = 8}
     */
    @EnumMember(
        value = 8L,
        name = "NETDEV_CHANGEADDR"
    )
    NETDEV_CHANGEADDR,

    /**
     * {@code NETDEV_PRE_CHANGEADDR = 9}
     */
    @EnumMember(
        value = 9L,
        name = "NETDEV_PRE_CHANGEADDR"
    )
    NETDEV_PRE_CHANGEADDR,

    /**
     * {@code NETDEV_GOING_DOWN = 10}
     */
    @EnumMember(
        value = 10L,
        name = "NETDEV_GOING_DOWN"
    )
    NETDEV_GOING_DOWN,

    /**
     * {@code NETDEV_CHANGENAME = 11}
     */
    @EnumMember(
        value = 11L,
        name = "NETDEV_CHANGENAME"
    )
    NETDEV_CHANGENAME,

    /**
     * {@code NETDEV_FEAT_CHANGE = 12}
     */
    @EnumMember(
        value = 12L,
        name = "NETDEV_FEAT_CHANGE"
    )
    NETDEV_FEAT_CHANGE,

    /**
     * {@code NETDEV_BONDING_FAILOVER = 13}
     */
    @EnumMember(
        value = 13L,
        name = "NETDEV_BONDING_FAILOVER"
    )
    NETDEV_BONDING_FAILOVER,

    /**
     * {@code NETDEV_PRE_UP = 14}
     */
    @EnumMember(
        value = 14L,
        name = "NETDEV_PRE_UP"
    )
    NETDEV_PRE_UP,

    /**
     * {@code NETDEV_PRE_TYPE_CHANGE = 15}
     */
    @EnumMember(
        value = 15L,
        name = "NETDEV_PRE_TYPE_CHANGE"
    )
    NETDEV_PRE_TYPE_CHANGE,

    /**
     * {@code NETDEV_POST_TYPE_CHANGE = 16}
     */
    @EnumMember(
        value = 16L,
        name = "NETDEV_POST_TYPE_CHANGE"
    )
    NETDEV_POST_TYPE_CHANGE,

    /**
     * {@code NETDEV_POST_INIT = 17}
     */
    @EnumMember(
        value = 17L,
        name = "NETDEV_POST_INIT"
    )
    NETDEV_POST_INIT,

    /**
     * {@code NETDEV_PRE_UNINIT = 18}
     */
    @EnumMember(
        value = 18L,
        name = "NETDEV_PRE_UNINIT"
    )
    NETDEV_PRE_UNINIT,

    /**
     * {@code NETDEV_RELEASE = 19}
     */
    @EnumMember(
        value = 19L,
        name = "NETDEV_RELEASE"
    )
    NETDEV_RELEASE,

    /**
     * {@code NETDEV_NOTIFY_PEERS = 20}
     */
    @EnumMember(
        value = 20L,
        name = "NETDEV_NOTIFY_PEERS"
    )
    NETDEV_NOTIFY_PEERS,

    /**
     * {@code NETDEV_JOIN = 21}
     */
    @EnumMember(
        value = 21L,
        name = "NETDEV_JOIN"
    )
    NETDEV_JOIN,

    /**
     * {@code NETDEV_CHANGEUPPER = 22}
     */
    @EnumMember(
        value = 22L,
        name = "NETDEV_CHANGEUPPER"
    )
    NETDEV_CHANGEUPPER,

    /**
     * {@code NETDEV_RESEND_IGMP = 23}
     */
    @EnumMember(
        value = 23L,
        name = "NETDEV_RESEND_IGMP"
    )
    NETDEV_RESEND_IGMP,

    /**
     * {@code NETDEV_PRECHANGEMTU = 24}
     */
    @EnumMember(
        value = 24L,
        name = "NETDEV_PRECHANGEMTU"
    )
    NETDEV_PRECHANGEMTU,

    /**
     * {@code NETDEV_CHANGEINFODATA = 25}
     */
    @EnumMember(
        value = 25L,
        name = "NETDEV_CHANGEINFODATA"
    )
    NETDEV_CHANGEINFODATA,

    /**
     * {@code NETDEV_BONDING_INFO = 26}
     */
    @EnumMember(
        value = 26L,
        name = "NETDEV_BONDING_INFO"
    )
    NETDEV_BONDING_INFO,

    /**
     * {@code NETDEV_PRECHANGEUPPER = 27}
     */
    @EnumMember(
        value = 27L,
        name = "NETDEV_PRECHANGEUPPER"
    )
    NETDEV_PRECHANGEUPPER,

    /**
     * {@code NETDEV_CHANGELOWERSTATE = 28}
     */
    @EnumMember(
        value = 28L,
        name = "NETDEV_CHANGELOWERSTATE"
    )
    NETDEV_CHANGELOWERSTATE,

    /**
     * {@code NETDEV_UDP_TUNNEL_PUSH_INFO = 29}
     */
    @EnumMember(
        value = 29L,
        name = "NETDEV_UDP_TUNNEL_PUSH_INFO"
    )
    NETDEV_UDP_TUNNEL_PUSH_INFO,

    /**
     * {@code NETDEV_UDP_TUNNEL_DROP_INFO = 30}
     */
    @EnumMember(
        value = 30L,
        name = "NETDEV_UDP_TUNNEL_DROP_INFO"
    )
    NETDEV_UDP_TUNNEL_DROP_INFO,

    /**
     * {@code NETDEV_CHANGE_TX_QUEUE_LEN = 31}
     */
    @EnumMember(
        value = 31L,
        name = "NETDEV_CHANGE_TX_QUEUE_LEN"
    )
    NETDEV_CHANGE_TX_QUEUE_LEN,

    /**
     * {@code NETDEV_CVLAN_FILTER_PUSH_INFO = 32}
     */
    @EnumMember(
        value = 32L,
        name = "NETDEV_CVLAN_FILTER_PUSH_INFO"
    )
    NETDEV_CVLAN_FILTER_PUSH_INFO,

    /**
     * {@code NETDEV_CVLAN_FILTER_DROP_INFO = 33}
     */
    @EnumMember(
        value = 33L,
        name = "NETDEV_CVLAN_FILTER_DROP_INFO"
    )
    NETDEV_CVLAN_FILTER_DROP_INFO,

    /**
     * {@code NETDEV_SVLAN_FILTER_PUSH_INFO = 34}
     */
    @EnumMember(
        value = 34L,
        name = "NETDEV_SVLAN_FILTER_PUSH_INFO"
    )
    NETDEV_SVLAN_FILTER_PUSH_INFO,

    /**
     * {@code NETDEV_SVLAN_FILTER_DROP_INFO = 35}
     */
    @EnumMember(
        value = 35L,
        name = "NETDEV_SVLAN_FILTER_DROP_INFO"
    )
    NETDEV_SVLAN_FILTER_DROP_INFO,

    /**
     * {@code NETDEV_OFFLOAD_XSTATS_ENABLE = 36}
     */
    @EnumMember(
        value = 36L,
        name = "NETDEV_OFFLOAD_XSTATS_ENABLE"
    )
    NETDEV_OFFLOAD_XSTATS_ENABLE,

    /**
     * {@code NETDEV_OFFLOAD_XSTATS_DISABLE = 37}
     */
    @EnumMember(
        value = 37L,
        name = "NETDEV_OFFLOAD_XSTATS_DISABLE"
    )
    NETDEV_OFFLOAD_XSTATS_DISABLE,

    /**
     * {@code NETDEV_OFFLOAD_XSTATS_REPORT_USED = 38}
     */
    @EnumMember(
        value = 38L,
        name = "NETDEV_OFFLOAD_XSTATS_REPORT_USED"
    )
    NETDEV_OFFLOAD_XSTATS_REPORT_USED,

    /**
     * {@code NETDEV_OFFLOAD_XSTATS_REPORT_DELTA = 39}
     */
    @EnumMember(
        value = 39L,
        name = "NETDEV_OFFLOAD_XSTATS_REPORT_DELTA"
    )
    NETDEV_OFFLOAD_XSTATS_REPORT_DELTA,

    /**
     * {@code NETDEV_XDP_FEAT_CHANGE = 40}
     */
    @EnumMember(
        value = 40L,
        name = "NETDEV_XDP_FEAT_CHANGE"
    )
    NETDEV_XDP_FEAT_CHANGE
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct netdev_notifier_info"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class netdev_notifier_info extends Struct {
    public Ptr<net_device> dev;

    public Ptr<netlink_ext_ack> extack;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct netdev_rx_queue"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class netdev_rx_queue extends Struct {
    public xdp_rxq_info xdp_rxq;

    public Ptr<rps_map> rps_map;

    public Ptr<rps_dev_flow_table> rps_flow_table;

    public kobject kobj;

    public Ptr<Ptr<attribute_group>> groups;

    public Ptr<net_device> dev;

    public @OriginalName("netdevice_tracker") lockdep_map_p dev_tracker;

    public Ptr<xsk_buff_pool> pool;

    public Ptr<napi_struct> napi;

    public pp_memory_provider_params mp_params;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "enum netdev_reg_state"
  )
  public enum netdev_reg_state implements Enum<netdev_reg_state>, TypedEnum<netdev_reg_state, java.lang. @Unsigned Integer> {
    /**
     * {@code NETREG_UNINITIALIZED = 0}
     */
    @EnumMember(
        value = 0L,
        name = "NETREG_UNINITIALIZED"
    )
    NETREG_UNINITIALIZED,

    /**
     * {@code NETREG_REGISTERED = 1}
     */
    @EnumMember(
        value = 1L,
        name = "NETREG_REGISTERED"
    )
    NETREG_REGISTERED,

    /**
     * {@code NETREG_UNREGISTERING = 2}
     */
    @EnumMember(
        value = 2L,
        name = "NETREG_UNREGISTERING"
    )
    NETREG_UNREGISTERING,

    /**
     * {@code NETREG_UNREGISTERED = 3}
     */
    @EnumMember(
        value = 3L,
        name = "NETREG_UNREGISTERED"
    )
    NETREG_UNREGISTERED,

    /**
     * {@code NETREG_RELEASED = 4}
     */
    @EnumMember(
        value = 4L,
        name = "NETREG_RELEASED"
    )
    NETREG_RELEASED,

    /**
     * {@code NETREG_DUMMY = 5}
     */
    @EnumMember(
        value = 5L,
        name = "NETREG_DUMMY"
    )
    NETREG_DUMMY
  }

  @Type(
      noCCodeGeneration = true,
      cType = "enum netdev_state_t"
  )
  public enum netdev_state_t implements Enum<netdev_state_t>, TypedEnum<netdev_state_t, java.lang. @Unsigned Integer> {
    /**
     * {@code __LINK_STATE_START = 0}
     */
    @EnumMember(
        value = 0L,
        name = "__LINK_STATE_START"
    )
    __LINK_STATE_START,

    /**
     * {@code __LINK_STATE_PRESENT = 1}
     */
    @EnumMember(
        value = 1L,
        name = "__LINK_STATE_PRESENT"
    )
    __LINK_STATE_PRESENT,

    /**
     * {@code __LINK_STATE_NOCARRIER = 2}
     */
    @EnumMember(
        value = 2L,
        name = "__LINK_STATE_NOCARRIER"
    )
    __LINK_STATE_NOCARRIER,

    /**
     * {@code __LINK_STATE_LINKWATCH_PENDING = 3}
     */
    @EnumMember(
        value = 3L,
        name = "__LINK_STATE_LINKWATCH_PENDING"
    )
    __LINK_STATE_LINKWATCH_PENDING,

    /**
     * {@code __LINK_STATE_DORMANT = 4}
     */
    @EnumMember(
        value = 4L,
        name = "__LINK_STATE_DORMANT"
    )
    __LINK_STATE_DORMANT,

    /**
     * {@code __LINK_STATE_TESTING = 5}
     */
    @EnumMember(
        value = 5L,
        name = "__LINK_STATE_TESTING"
    )
    __LINK_STATE_TESTING
  }

  @Type(
      noCCodeGeneration = true,
      cType = "enum netdev_queue_state_t"
  )
  public enum netdev_queue_state_t implements Enum<netdev_queue_state_t>, TypedEnum<netdev_queue_state_t, java.lang. @Unsigned Integer> {
    /**
     * {@code __QUEUE_STATE_DRV_XOFF = 0}
     */
    @EnumMember(
        value = 0L,
        name = "__QUEUE_STATE_DRV_XOFF"
    )
    __QUEUE_STATE_DRV_XOFF,

    /**
     * {@code __QUEUE_STATE_STACK_XOFF = 1}
     */
    @EnumMember(
        value = 1L,
        name = "__QUEUE_STATE_STACK_XOFF"
    )
    __QUEUE_STATE_STACK_XOFF,

    /**
     * {@code __QUEUE_STATE_FROZEN = 2}
     */
    @EnumMember(
        value = 2L,
        name = "__QUEUE_STATE_FROZEN"
    )
    __QUEUE_STATE_FROZEN
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct netdev_xmit"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class netdev_xmit extends Struct {
    public @Unsigned short recursion;

    public char more;

    public char skip_txqueue;

    public char sched_mirred_nest;

    public char nf_dup_skb_recursion;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "enum netdev_queue_type"
  )
  public enum netdev_queue_type implements Enum<netdev_queue_type>, TypedEnum<netdev_queue_type, java.lang. @Unsigned Integer> {
    /**
     * {@code NETDEV_QUEUE_TYPE_RX = 0}
     */
    @EnumMember(
        value = 0L,
        name = "NETDEV_QUEUE_TYPE_RX"
    )
    NETDEV_QUEUE_TYPE_RX,

    /**
     * {@code NETDEV_QUEUE_TYPE_TX = 1}
     */
    @EnumMember(
        value = 1L,
        name = "NETDEV_QUEUE_TYPE_TX"
    )
    NETDEV_QUEUE_TYPE_TX
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct netdev_hw_addr"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class netdev_hw_addr extends Struct {
    public list_head list;

    public rb_node node;

    public char @Size(32) [] addr;

    public char type;

    public boolean global_use;

    public int sync_cnt;

    public int refcount;

    public int synced;

    public callback_head callback_head;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct netdev_config"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class netdev_config extends Struct {
    public @Unsigned int hds_thresh;

    public char hds_config;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct netdev_queue_stats_rx"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class netdev_queue_stats_rx extends Struct {
    public @Unsigned long bytes;

    public @Unsigned long packets;

    public @Unsigned long alloc_fail;

    public @Unsigned long hw_drops;

    public @Unsigned long hw_drop_overruns;

    public @Unsigned long csum_complete;

    public @Unsigned long csum_unnecessary;

    public @Unsigned long csum_none;

    public @Unsigned long csum_bad;

    public @Unsigned long hw_gro_packets;

    public @Unsigned long hw_gro_bytes;

    public @Unsigned long hw_gro_wire_packets;

    public @Unsigned long hw_gro_wire_bytes;

    public @Unsigned long hw_drop_ratelimits;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct netdev_queue_stats_tx"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class netdev_queue_stats_tx extends Struct {
    public @Unsigned long bytes;

    public @Unsigned long packets;

    public @Unsigned long hw_drops;

    public @Unsigned long hw_drop_errors;

    public @Unsigned long csum_none;

    public @Unsigned long needs_csum;

    public @Unsigned long hw_gso_packets;

    public @Unsigned long hw_gso_bytes;

    public @Unsigned long hw_gso_wire_packets;

    public @Unsigned long hw_gso_wire_bytes;

    public @Unsigned long hw_drop_ratelimits;

    public @Unsigned long stop;

    public @Unsigned long wake;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct netdev_lag_lower_state_info"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class netdev_lag_lower_state_info extends Struct {
    public char link_up;

    public char tx_enabled;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct netdev_name_node"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class netdev_name_node extends Struct {
    public hlist_node hlist;

    public list_head list;

    public Ptr<net_device> dev;

    public String name;

    public callback_head rcu;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "enum netdev_lag_tx_type"
  )
  public enum netdev_lag_tx_type implements Enum<netdev_lag_tx_type>, TypedEnum<netdev_lag_tx_type, java.lang. @Unsigned Integer> {
    /**
     * {@code NETDEV_LAG_TX_TYPE_UNKNOWN = 0}
     */
    @EnumMember(
        value = 0L,
        name = "NETDEV_LAG_TX_TYPE_UNKNOWN"
    )
    NETDEV_LAG_TX_TYPE_UNKNOWN,

    /**
     * {@code NETDEV_LAG_TX_TYPE_RANDOM = 1}
     */
    @EnumMember(
        value = 1L,
        name = "NETDEV_LAG_TX_TYPE_RANDOM"
    )
    NETDEV_LAG_TX_TYPE_RANDOM,

    /**
     * {@code NETDEV_LAG_TX_TYPE_BROADCAST = 2}
     */
    @EnumMember(
        value = 2L,
        name = "NETDEV_LAG_TX_TYPE_BROADCAST"
    )
    NETDEV_LAG_TX_TYPE_BROADCAST,

    /**
     * {@code NETDEV_LAG_TX_TYPE_ROUNDROBIN = 3}
     */
    @EnumMember(
        value = 3L,
        name = "NETDEV_LAG_TX_TYPE_ROUNDROBIN"
    )
    NETDEV_LAG_TX_TYPE_ROUNDROBIN,

    /**
     * {@code NETDEV_LAG_TX_TYPE_ACTIVEBACKUP = 4}
     */
    @EnumMember(
        value = 4L,
        name = "NETDEV_LAG_TX_TYPE_ACTIVEBACKUP"
    )
    NETDEV_LAG_TX_TYPE_ACTIVEBACKUP,

    /**
     * {@code NETDEV_LAG_TX_TYPE_HASH = 5}
     */
    @EnumMember(
        value = 5L,
        name = "NETDEV_LAG_TX_TYPE_HASH"
    )
    NETDEV_LAG_TX_TYPE_HASH
  }

  @Type(
      noCCodeGeneration = true,
      cType = "enum netdev_lag_hash"
  )
  public enum netdev_lag_hash implements Enum<netdev_lag_hash>, TypedEnum<netdev_lag_hash, java.lang. @Unsigned Integer> {
    /**
     * {@code NETDEV_LAG_HASH_NONE = 0}
     */
    @EnumMember(
        value = 0L,
        name = "NETDEV_LAG_HASH_NONE"
    )
    NETDEV_LAG_HASH_NONE,

    /**
     * {@code NETDEV_LAG_HASH_L2 = 1}
     */
    @EnumMember(
        value = 1L,
        name = "NETDEV_LAG_HASH_L2"
    )
    NETDEV_LAG_HASH_L2,

    /**
     * {@code NETDEV_LAG_HASH_L34 = 2}
     */
    @EnumMember(
        value = 2L,
        name = "NETDEV_LAG_HASH_L34"
    )
    NETDEV_LAG_HASH_L34,

    /**
     * {@code NETDEV_LAG_HASH_L23 = 3}
     */
    @EnumMember(
        value = 3L,
        name = "NETDEV_LAG_HASH_L23"
    )
    NETDEV_LAG_HASH_L23,

    /**
     * {@code NETDEV_LAG_HASH_E23 = 4}
     */
    @EnumMember(
        value = 4L,
        name = "NETDEV_LAG_HASH_E23"
    )
    NETDEV_LAG_HASH_E23,

    /**
     * {@code NETDEV_LAG_HASH_E34 = 5}
     */
    @EnumMember(
        value = 5L,
        name = "NETDEV_LAG_HASH_E34"
    )
    NETDEV_LAG_HASH_E34,

    /**
     * {@code NETDEV_LAG_HASH_VLAN_SRCMAC = 6}
     */
    @EnumMember(
        value = 6L,
        name = "NETDEV_LAG_HASH_VLAN_SRCMAC"
    )
    NETDEV_LAG_HASH_VLAN_SRCMAC,

    /**
     * {@code NETDEV_LAG_HASH_UNKNOWN = 7}
     */
    @EnumMember(
        value = 7L,
        name = "NETDEV_LAG_HASH_UNKNOWN"
    )
    NETDEV_LAG_HASH_UNKNOWN
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct netdev_lag_upper_info"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class netdev_lag_upper_info extends Struct {
    public netdev_lag_tx_type tx_type;

    public netdev_lag_hash hash_type;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct netdev_notifier_changeupper_info"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class netdev_notifier_changeupper_info extends Struct {
    public netdev_notifier_info info;

    public Ptr<net_device> upper_dev;

    public boolean master;

    public boolean linking;

    public Ptr<?> upper_info;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "enum netdev_napi_threaded"
  )
  public enum netdev_napi_threaded implements Enum<netdev_napi_threaded>, TypedEnum<netdev_napi_threaded, java.lang. @Unsigned Integer> {
    /**
     * {@code NETDEV_NAPI_THREADED_DISABLED = 0}
     */
    @EnumMember(
        value = 0L,
        name = "NETDEV_NAPI_THREADED_DISABLED"
    )
    NETDEV_NAPI_THREADED_DISABLED,

    /**
     * {@code NETDEV_NAPI_THREADED_ENABLED = 1}
     */
    @EnumMember(
        value = 1L,
        name = "NETDEV_NAPI_THREADED_ENABLED"
    )
    NETDEV_NAPI_THREADED_ENABLED
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct netdev_net_notifier"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class netdev_net_notifier extends Struct {
    public list_head list;

    public Ptr<notifier_block> nb;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct netdev_notifier_info_ext"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class netdev_notifier_info_ext extends Struct {
    public netdev_notifier_info info;

    public ext_of_netdev_notifier_info_ext ext;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct netdev_notifier_change_info"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class netdev_notifier_change_info extends Struct {
    public netdev_notifier_info info;

    public @Unsigned int flags_changed;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct netdev_notifier_changelowerstate_info"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class netdev_notifier_changelowerstate_info extends Struct {
    public netdev_notifier_info info;

    public Ptr<?> lower_state_info;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct netdev_notifier_pre_changeaddr_info"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class netdev_notifier_pre_changeaddr_info extends Struct {
    public netdev_notifier_info info;

    public String dev_addr;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "enum netdev_offload_xstats_type"
  )
  public enum netdev_offload_xstats_type implements Enum<netdev_offload_xstats_type>, TypedEnum<netdev_offload_xstats_type, java.lang. @Unsigned Integer> {
    /**
     * {@code NETDEV_OFFLOAD_XSTATS_TYPE_L3 = 1}
     */
    @EnumMember(
        value = 1L,
        name = "NETDEV_OFFLOAD_XSTATS_TYPE_L3"
    )
    NETDEV_OFFLOAD_XSTATS_TYPE_L3
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct netdev_notifier_offload_xstats_rd"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class netdev_notifier_offload_xstats_rd extends Struct {
    public rtnl_hw_stats64 stats;

    public boolean used;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct netdev_notifier_offload_xstats_ru"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class netdev_notifier_offload_xstats_ru extends Struct {
    public boolean used;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct netdev_notifier_offload_xstats_info"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class netdev_notifier_offload_xstats_info extends Struct {
    public netdev_notifier_info info;

    public netdev_offload_xstats_type type;

    @InlineUnion(58143)
    public Ptr<netdev_notifier_offload_xstats_rd> report_delta;

    @InlineUnion(58143)
    public Ptr<netdev_notifier_offload_xstats_ru> report_used;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct netdev_nested_priv"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class netdev_nested_priv extends Struct {
    public char flags;

    public Ptr<?> data;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct netdev_bonding_info"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class netdev_bonding_info extends Struct {
    public ifslave slave;

    public ifbond master;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct netdev_notifier_bonding_info"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class netdev_notifier_bonding_info extends Struct {
    public netdev_notifier_info info;

    public netdev_bonding_info bonding_info;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct netdev_adjacent"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class netdev_adjacent extends Struct {
    public Ptr<net_device> dev;

    public @OriginalName("netdevice_tracker") lockdep_map_p dev_tracker;

    public boolean master;

    public boolean ignore;

    public @Unsigned short ref_nr;

    public Ptr<?> _private;

    public list_head list;

    public callback_head rcu;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "enum netdev_xdp_rx_metadata"
  )
  public enum netdev_xdp_rx_metadata implements Enum<netdev_xdp_rx_metadata>, TypedEnum<netdev_xdp_rx_metadata, java.lang. @Unsigned Integer> {
    /**
     * {@code NETDEV_XDP_RX_METADATA_TIMESTAMP = 1}
     */
    @EnumMember(
        value = 1L,
        name = "NETDEV_XDP_RX_METADATA_TIMESTAMP"
    )
    NETDEV_XDP_RX_METADATA_TIMESTAMP,

    /**
     * {@code NETDEV_XDP_RX_METADATA_HASH = 2}
     */
    @EnumMember(
        value = 2L,
        name = "NETDEV_XDP_RX_METADATA_HASH"
    )
    NETDEV_XDP_RX_METADATA_HASH,

    /**
     * {@code NETDEV_XDP_RX_METADATA_VLAN_TAG = 4}
     */
    @EnumMember(
        value = 4L,
        name = "NETDEV_XDP_RX_METADATA_VLAN_TAG"
    )
    NETDEV_XDP_RX_METADATA_VLAN_TAG
  }

  @Type(
      noCCodeGeneration = true,
      cType = "enum netdev_xsk_flags"
  )
  public enum netdev_xsk_flags implements Enum<netdev_xsk_flags>, TypedEnum<netdev_xsk_flags, java.lang. @Unsigned Integer> {
    /**
     * {@code NETDEV_XSK_FLAGS_TX_TIMESTAMP = 1}
     */
    @EnumMember(
        value = 1L,
        name = "NETDEV_XSK_FLAGS_TX_TIMESTAMP"
    )
    NETDEV_XSK_FLAGS_TX_TIMESTAMP,

    /**
     * {@code NETDEV_XSK_FLAGS_TX_CHECKSUM = 2}
     */
    @EnumMember(
        value = 2L,
        name = "NETDEV_XSK_FLAGS_TX_CHECKSUM"
    )
    NETDEV_XSK_FLAGS_TX_CHECKSUM,

    /**
     * {@code NETDEV_XSK_FLAGS_TX_LAUNCH_TIME_FIFO = 4}
     */
    @EnumMember(
        value = 4L,
        name = "NETDEV_XSK_FLAGS_TX_LAUNCH_TIME_FIFO"
    )
    NETDEV_XSK_FLAGS_TX_LAUNCH_TIME_FIFO
  }

  @Type(
      noCCodeGeneration = true,
      cType = "enum netdev_qstats_scope"
  )
  public enum netdev_qstats_scope implements Enum<netdev_qstats_scope>, TypedEnum<netdev_qstats_scope, java.lang. @Unsigned Integer> {
    /**
     * {@code NETDEV_QSTATS_SCOPE_QUEUE = 1}
     */
    @EnumMember(
        value = 1L,
        name = "NETDEV_QSTATS_SCOPE_QUEUE"
    )
    NETDEV_QSTATS_SCOPE_QUEUE
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct netdev_nl_sock"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class netdev_nl_sock extends Struct {
    public mutex lock;

    public list_head bindings;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct netdev_nl_dump_ctx"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class netdev_nl_dump_ctx extends Struct {
    public @Unsigned long ifindex;

    public @Unsigned int rxq_idx;

    public @Unsigned int txq_idx;

    public @Unsigned int napi_id;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct netdev_queue_attribute"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class netdev_queue_attribute extends Struct {
    public attribute attr;

    public Ptr<?> show;

    public Ptr<?> store;
  }
}
