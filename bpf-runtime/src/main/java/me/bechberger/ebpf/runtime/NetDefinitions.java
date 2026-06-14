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
import static me.bechberger.ebpf.runtime.NetdevDefinitions.*;
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
 * Generated class for BPF runtime types that start with net
 */
@java.lang.SuppressWarnings("unused")
public final class NetDefinitions {
  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __net_devmem_dmabuf_binding_free(Ptr<work_struct> wq) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("__net_mp_close_rxq($arg1, $arg2, (const struct pp_memory_provider_params*)$arg3)")
  public static void __net_mp_close_rxq(Ptr<net_device> dev, @Unsigned int ifq_idx,
      Ptr<pp_memory_provider_params> old_p) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("__net_mp_open_rxq($arg1, $arg2, (const struct pp_memory_provider_params*)$arg3, $arg4)")
  public static int __net_mp_open_rxq(Ptr<net_device> dev, @Unsigned int rxq_idx,
      Ptr<pp_memory_provider_params> p, Ptr<netlink_ext_ack> extack) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int __net_shaper_delete(Ptr<net_shaper_binding> binding, Ptr<net_shaper> shaper,
      Ptr<netlink_ext_ack> extack) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int __net_shaper_group(Ptr<net_shaper_binding> binding, boolean update_node,
      int leaves_count, Ptr<net_shaper> leaves, Ptr<net_shaper> node, Ptr<netlink_ext_ack> extack) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int __net_test_loopback(Ptr<net_device> ndev, Ptr<net_packet_attrs> attr) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static Ptr<net_generic> net_alloc_generic() {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int net_assign_generic(Ptr<net> net, @Unsigned int id, Ptr<?> data) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static Ptr<ctl_table_set> net_ctl_header_lookup(Ptr<ctl_table_root> root) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("net_ctl_permissions($arg1, (const struct ctl_table*)$arg2)")
  public static int net_ctl_permissions(Ptr<ctl_table_header> head, Ptr<ctl_table> table) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void net_ctl_set_ownership(Ptr<ctl_table_header> head, Ptr<kuid_t> uid,
      Ptr<kgid_t> gid) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static boolean net_current_may_mount() {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void net_dec_egress_queue() {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void net_dec_ingress_queue() {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int net_dev_init() {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static Ptr<net_iov> net_devmem_alloc_dmabuf(Ptr<net_devmem_dmabuf_binding> binding) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static Ptr<net_devmem_dmabuf_binding> net_devmem_bind_dmabuf(Ptr<net_device> dev,
      dma_data_direction direction, @Unsigned int dmabuf_fd, Ptr<netdev_nl_sock> priv,
      Ptr<netlink_ext_ack> extack) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int net_devmem_bind_dmabuf_to_queue(Ptr<net_device> dev, @Unsigned int rxq_idx,
      Ptr<net_devmem_dmabuf_binding> binding, Ptr<netlink_ext_ack> extack) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void net_devmem_dmabuf_free_chunk_owner(Ptr<gen_pool> genpool,
      Ptr<gen_pool_chunk> chunk, Ptr<?> not_used) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void net_devmem_free_dmabuf(Ptr<net_iov> niov) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static Ptr<net_devmem_dmabuf_binding> net_devmem_get_binding(Ptr<sock> sk,
      @Unsigned int dmabuf_id) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void net_devmem_get_net_iov(Ptr<net_iov> niov) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static Ptr<net_iov> net_devmem_get_niov_at(Ptr<net_devmem_dmabuf_binding> binding,
      @Unsigned long virt_addr, Ptr<java.lang. @Unsigned Long> off,
      Ptr<java.lang. @Unsigned Long> size) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static Ptr<net_devmem_dmabuf_binding> net_devmem_lookup_dmabuf(@Unsigned int id) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void net_devmem_put_net_iov(Ptr<net_iov> niov) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void net_devmem_unbind_dmabuf(Ptr<net_devmem_dmabuf_binding> binding) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("net_dim($arg1, (const struct dim_sample*)$arg2)")
  public static void net_dim(Ptr<dim> dim, Ptr<dim_sample> end_sample) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void net_dim_free_irq_moder(Ptr<net_device> dev) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("net_dim_init_irq_moder($arg1, $arg2, $arg3, $arg4, $arg5, (void (*)(struct work_struct*))$arg6, (void (*)(struct work_struct*))$arg7)")
  public static int net_dim_init_irq_moder(Ptr<net_device> dev, char profile_flags, char coal_flags,
      char rx_mode, char tx_mode, Ptr<?> rx_dim_work, Ptr<?> tx_dim_work) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void net_dim_set_rx_mode(Ptr<net_device> dev, char rx_mode) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void net_dim_set_tx_mode(Ptr<net_device> dev, char tx_mode) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void net_dim_setting(Ptr<net_device> dev, Ptr<dim> dim, boolean is_tx) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int net_dim_stats_compare(Ptr<dim_stats> curr, Ptr<dim_stats> prev) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int net_dim_step(Ptr<dim> dim) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void net_dim_work_cancel(Ptr<dim> dim) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void net_disable_timestamp() {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int net_dm_cmd_config(Ptr<sk_buff> skb, Ptr<genl_info> info) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int net_dm_cmd_config_get(Ptr<sk_buff> skb, Ptr<genl_info> info) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int net_dm_cmd_stats_get(Ptr<sk_buff> skb, Ptr<genl_info> info) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int net_dm_cmd_trace(Ptr<sk_buff> skb, Ptr<genl_info> info) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int net_dm_hw_monitor_start(Ptr<netlink_ext_ack> extack) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void net_dm_hw_monitor_stop(Ptr<netlink_ext_ack> extack) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int net_dm_hw_packet_report_fill(Ptr<sk_buff> msg, Ptr<sk_buff> skb,
      @Unsigned long payload_len) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("net_dm_hw_packet_report_size($arg1, (const struct devlink_trap_metadata*)$arg2)")
  public static @Unsigned long net_dm_hw_packet_report_size(@Unsigned long payload_len,
      Ptr<devlink_trap_metadata> hw_metadata) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void net_dm_hw_packet_work(Ptr<work_struct> work) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static Ptr<net_dm_hw_entries> net_dm_hw_reset_per_cpu_data(Ptr<per_cpu_dm_data> hw_data) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("net_dm_hw_summary_report_fill($arg1, (const struct net_dm_hw_entries*)$arg2)")
  public static int net_dm_hw_summary_report_fill(Ptr<sk_buff> msg,
      Ptr<net_dm_hw_entries> hw_entries) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void net_dm_hw_summary_work(Ptr<work_struct> work) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("net_dm_hw_trap_packet_probe($arg1, (const struct devlink*)$arg2, $arg3, (const struct devlink_trap_metadata*)$arg4)")
  public static void net_dm_hw_trap_packet_probe(Ptr<?> ignore, Ptr<devlink> devlink,
      Ptr<sk_buff> skb, Ptr<devlink_trap_metadata> metadata) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("net_dm_hw_trap_summary_probe($arg1, (const struct devlink*)$arg2, $arg3, (const struct devlink_trap_metadata*)$arg4)")
  public static void net_dm_hw_trap_summary_probe(Ptr<?> ignore, Ptr<devlink> devlink,
      Ptr<sk_buff> skb, Ptr<devlink_trap_metadata> metadata) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("net_dm_nl_post_doit((const struct genl_split_ops*)$arg1, $arg2, $arg3)")
  public static void net_dm_nl_post_doit(Ptr<genl_split_ops> ops, Ptr<sk_buff> skb,
      Ptr<genl_info> info) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("net_dm_nl_pre_doit((const struct genl_split_ops*)$arg1, $arg2, $arg3)")
  public static int net_dm_nl_pre_doit(Ptr<genl_split_ops> ops, Ptr<sk_buff> skb,
      Ptr<genl_info> info) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int net_dm_packet_report_fill(Ptr<sk_buff> msg, Ptr<sk_buff> skb,
      @Unsigned long payload_len) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("net_dm_packet_report_in_port_put($arg1, $arg2, (const u8*)$arg3)")
  public static int net_dm_packet_report_in_port_put(Ptr<sk_buff> msg, int ifindex, String name) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void net_dm_packet_trace_kfree_skb_hit(Ptr<?> ignore, Ptr<sk_buff> skb,
      Ptr<?> location, skb_drop_reason reason, Ptr<sock> rx_sk) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void net_dm_packet_trace_napi_poll_hit(Ptr<?> ignore, Ptr<napi_struct> napi,
      int work, int budget) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void net_dm_packet_work(Ptr<work_struct> work) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void net_dm_trace_off_set() {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int net_dm_trace_on_set(Ptr<netlink_ext_ack> extack) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void net_drop_ns(Ptr<?> p) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void net_enable_timestamp() {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int net_eq_idr(int id, Ptr<?> net, Ptr<?> peer) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int net_failover_change_mtu(Ptr<net_device> dev, int new_mtu) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int net_failover_close(Ptr<net_device> dev) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void net_failover_compute_features(Ptr<net_device> dev) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static Ptr<failover> net_failover_create(Ptr<net_device> standby_dev) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void net_failover_destroy(Ptr<failover> failover) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void net_failover_exit() {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("net_failover_fold_stats($arg1, (const struct rtnl_link_stats64*)$arg2, (const struct rtnl_link_stats64*)$arg3)")
  public static void net_failover_fold_stats(Ptr<rtnl_link_stats64> _res,
      Ptr<rtnl_link_stats64> _new, Ptr<rtnl_link_stats64> _old) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void net_failover_get_stats(Ptr<net_device> dev, Ptr<rtnl_link_stats64> stats) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static @OriginalName("rx_handler_result_t") rx_handler_result net_failover_handle_frame(
      Ptr<Ptr<sk_buff>> pskb) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int net_failover_init() {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void net_failover_lower_state_changed(Ptr<net_device> slave_dev,
      Ptr<net_device> primary_dev, Ptr<net_device> standby_dev) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int net_failover_open(Ptr<net_device> dev) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static @Unsigned short net_failover_select_queue(Ptr<net_device> dev, Ptr<sk_buff> skb,
      Ptr<net_device> sb_dev) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void net_failover_set_rx_mode(Ptr<net_device> dev) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int net_failover_slave_link_change(Ptr<net_device> slave_dev,
      Ptr<net_device> failover_dev) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int net_failover_slave_name_change(Ptr<net_device> slave_dev,
      Ptr<net_device> failover_dev) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int net_failover_slave_pre_register(Ptr<net_device> slave_dev,
      Ptr<net_device> failover_dev) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int net_failover_slave_pre_unregister(Ptr<net_device> slave_dev,
      Ptr<net_device> failover_dev) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int net_failover_slave_register(Ptr<net_device> slave_dev,
      Ptr<net_device> failover_dev) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int net_failover_slave_unregister(Ptr<net_device> slave_dev,
      Ptr<net_device> failover_dev) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static @OriginalName("netdev_tx_t") netdev_tx net_failover_start_xmit(Ptr<sk_buff> skb,
      Ptr<net_device> dev) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int net_failover_vlan_rx_add_vid(Ptr<net_device> dev,
      @Unsigned @OriginalName("__be16") short proto, @Unsigned short vid) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int net_failover_vlan_rx_kill_vid(Ptr<net_device> dev,
      @Unsigned @OriginalName("__be16") short proto, @Unsigned short vid) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static boolean net_failover_xmit_ready(Ptr<net_device> dev) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("net_get_ownership((const struct device*)$arg1, $arg2, $arg3)")
  public static void net_get_ownership(Ptr<device> d, Ptr<kuid_t> uid, Ptr<kgid_t> gid) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static Ptr<?> net_grab_current_ns() {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("net_hwtstamp_validate((const struct kernel_hwtstamp_config*)$arg1)")
  public static int net_hwtstamp_validate(Ptr<kernel_hwtstamp_config> cfg) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void net_inc_egress_queue() {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void net_inc_ingress_queue() {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("((const void*)net_initial_ns())")
  public static Ptr<?> net_initial_ns() {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int net_inuse_init() {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static boolean net_is_devmem_iov(Ptr<net_iov> niov) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void net_mp_close_rxq(Ptr<net_device> dev, @Unsigned int ifq_idx,
      Ptr<pp_memory_provider_params> old_p) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void net_mp_niov_clear_page_pool(Ptr<net_iov> niov) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static boolean net_mp_niov_set_dma_addr(Ptr<net_iov> niov,
      @Unsigned @OriginalName("dma_addr_t") long addr) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void net_mp_niov_set_page_pool(Ptr<page_pool> pool, Ptr<net_iov> niov) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int net_mp_open_rxq(Ptr<net_device> dev, @Unsigned int rxq_idx,
      Ptr<pp_memory_provider_params> p) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("((const void*)net_namespace((const struct device*)$arg1))")
  public static Ptr<?> net_namespace(Ptr<device> d) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("((const void*)net_netlink_ns($arg1))")
  public static Ptr<?> net_netlink_ns(Ptr<sock> sk) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void net_ns_barrier() {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("net_ns_get_ownership((const struct net*)$arg1, $arg2, $arg3)")
  public static void net_ns_get_ownership(Ptr<net> net, Ptr<kuid_t> uid, Ptr<kgid_t> gid) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void net_ns_init() {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void net_ns_net_exit(Ptr<net> net) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int net_ns_net_init(Ptr<net> net) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void net_passive_dec(Ptr<net> net) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void net_prio_attach(Ptr<cgroup_taskset> tset) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int net_ratelimit() {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void net_rps_action_and_irq_enable(Ptr<softnet_data> sd) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void net_rps_send_ipi(Ptr<softnet_data> remsd) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void net_rx_action() {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int net_rx_queue_update_kobjects(Ptr<net_device> dev, int old_num, int new_num) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void net_selftest(Ptr<net_device> ndev, Ptr<ethtool_test> etest,
      Ptr<java.lang. @Unsigned Long> buf) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int net_selftest_get_count() {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void net_selftest_get_strings(Ptr<java.lang.Character> data) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("net_shaper_cap_fill_one($arg1, $arg2, $arg3, $arg4, (const struct genl_info*)$arg5)")
  public static int net_shaper_cap_fill_one(Ptr<sk_buff> msg, Ptr<net_shaper_binding> binding,
      net_shaper_scope scope, @Unsigned long flags, Ptr<genl_info> info) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("net_shaper_commit($arg1, $arg2, (const struct net_shaper*)$arg3)")
  public static void net_shaper_commit(Ptr<net_shaper_binding> binding, int nr_shapers,
      Ptr<net_shaper> shapers) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("net_shaper_ctx_setup((const struct genl_info*)$arg1, $arg2, $arg3)")
  public static int net_shaper_ctx_setup(Ptr<genl_info> info, int type,
      Ptr<net_shaper_nl_ctx> ctx) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("net_shaper_fill_handle($arg1, (const struct net_shaper_handle*)$arg2, $arg3)")
  public static int net_shaper_fill_handle(Ptr<sk_buff> msg, Ptr<net_shaper_handle> handle,
      @Unsigned int type) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("net_shaper_fill_one($arg1, (const struct net_shaper_binding*)$arg2, (const struct net_shaper*)$arg3, (const struct genl_info*)$arg4)")
  public static int net_shaper_fill_one(Ptr<sk_buff> msg, Ptr<net_shaper_binding> binding,
      Ptr<net_shaper> shaper, Ptr<genl_info> info) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void net_shaper_flush_netdev(Ptr<net_device> dev) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("net_shaper_handle_cmp((const struct net_shaper_handle*)$arg1, (const struct net_shaper_handle*)$arg2)")
  public static int net_shaper_handle_cmp(Ptr<net_shaper_handle> a, Ptr<net_shaper_handle> b) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static Ptr<net_shaper_hierarchy> net_shaper_hierarchy_setup(
      Ptr<net_shaper_binding> binding) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("net_shaper_lookup($arg1, (const struct net_shaper_handle*)$arg2)")
  public static Ptr<net_shaper> net_shaper_lookup(Ptr<net_shaper_binding> binding,
      Ptr<net_shaper_handle> handle) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int net_shaper_nl_cap_get_doit(Ptr<sk_buff> skb, Ptr<genl_info> info) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int net_shaper_nl_cap_get_dumpit(Ptr<sk_buff> skb, Ptr<netlink_callback> cb) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("net_shaper_nl_cap_post_doit((const struct genl_split_ops*)$arg1, $arg2, $arg3)")
  public static void net_shaper_nl_cap_post_doit(Ptr<genl_split_ops> ops, Ptr<sk_buff> skb,
      Ptr<genl_info> info) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int net_shaper_nl_cap_post_dumpit(Ptr<netlink_callback> cb) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("net_shaper_nl_cap_pre_doit((const struct genl_split_ops*)$arg1, $arg2, $arg3)")
  public static int net_shaper_nl_cap_pre_doit(Ptr<genl_split_ops> ops, Ptr<sk_buff> skb,
      Ptr<genl_info> info) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int net_shaper_nl_cap_pre_dumpit(Ptr<netlink_callback> cb) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int net_shaper_nl_delete_doit(Ptr<sk_buff> skb, Ptr<genl_info> info) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int net_shaper_nl_get_doit(Ptr<sk_buff> skb, Ptr<genl_info> info) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int net_shaper_nl_get_dumpit(Ptr<sk_buff> skb, Ptr<netlink_callback> cb) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int net_shaper_nl_group_doit(Ptr<sk_buff> skb, Ptr<genl_info> info) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("net_shaper_nl_post_doit((const struct genl_split_ops*)$arg1, $arg2, $arg3)")
  public static void net_shaper_nl_post_doit(Ptr<genl_split_ops> ops, Ptr<sk_buff> skb,
      Ptr<genl_info> info) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int net_shaper_nl_post_dumpit(Ptr<netlink_callback> cb) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("net_shaper_nl_pre_doit((const struct genl_split_ops*)$arg1, $arg2, $arg3)")
  public static int net_shaper_nl_pre_doit(Ptr<genl_split_ops> ops, Ptr<sk_buff> skb,
      Ptr<genl_info> info) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int net_shaper_nl_pre_dumpit(Ptr<netlink_callback> cb) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int net_shaper_nl_set_doit(Ptr<sk_buff> skb, Ptr<genl_info> info) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("net_shaper_parse_handle((const struct nlattr*)$arg1, (const struct genl_info*)$arg2, $arg3)")
  public static int net_shaper_parse_handle(Ptr<nlattr> attr, Ptr<genl_info> info,
      Ptr<net_shaper_handle> handle) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("net_shaper_parse_info($arg1, $arg2, (const struct genl_info*)$arg3, $arg4, $arg5)")
  public static int net_shaper_parse_info(Ptr<net_shaper_binding> binding, Ptr<Ptr<nlattr>> tb,
      Ptr<genl_info> info, Ptr<net_shaper> shaper,
      Ptr<java.lang. @OriginalName("bool") Boolean> exists) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("net_shaper_parse_leaf($arg1, (const struct nlattr*)$arg2, (const struct genl_info*)$arg3, (const struct net_shaper*)$arg4, $arg5)")
  public static int net_shaper_parse_leaf(Ptr<net_shaper_binding> binding, Ptr<nlattr> attr,
      Ptr<genl_info> info, Ptr<net_shaper> node, Ptr<net_shaper> shaper) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("net_shaper_pre_del_node($arg1, (const struct net_shaper*)$arg2, $arg3)")
  public static int net_shaper_pre_del_node(Ptr<net_shaper_binding> binding, Ptr<net_shaper> shaper,
      Ptr<netlink_ext_ack> extack) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int net_shaper_pre_insert(Ptr<net_shaper_binding> binding,
      Ptr<net_shaper_handle> handle, Ptr<netlink_ext_ack> extack) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void net_shaper_rollback(Ptr<net_shaper_binding> binding) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void net_shaper_set_real_num_tx_queues(Ptr<net_device> dev, @Unsigned int txq) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("net_shaper_validate_caps($arg1, $arg2, (const struct genl_info*)$arg3, $arg4)")
  public static int net_shaper_validate_caps(Ptr<net_shaper_binding> binding, Ptr<Ptr<nlattr>> tb,
      Ptr<genl_info> info, Ptr<net_shaper> shaper) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("net_shaper_validate_nesting($arg1, (const struct net_shaper*)$arg2, $arg3)")
  public static int net_shaper_validate_nesting(Ptr<net_shaper_binding> binding,
      Ptr<net_shaper> shaper, Ptr<netlink_ext_ack> extack) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static boolean net_support_hwtstamp_qualifier(Ptr<net_device> dev,
      hwtstamp_provider_qualifier qualifier) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int net_sysctl_init() {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static Ptr<sk_buff> net_test_get_skb(Ptr<net_device> ndev, Ptr<net_packet_attrs> attr) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int net_test_loopback_validate(Ptr<sk_buff> skb, Ptr<net_device> ndev,
      Ptr<packet_type> pt, Ptr<net_device> orig_ndev) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int net_test_netif_carrier(Ptr<net_device> ndev) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int net_test_phy_loopback_disable(Ptr<net_device> ndev) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int net_test_phy_loopback_enable(Ptr<net_device> ndev) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int net_test_phy_loopback_tcp(Ptr<net_device> ndev) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int net_test_phy_loopback_tcp_bad_csum(Ptr<net_device> ndev) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int net_test_phy_loopback_udp(Ptr<net_device> ndev) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int net_test_phy_loopback_udp_mtu(Ptr<net_device> ndev) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int net_test_phy_phydev(Ptr<net_device> ndev) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void net_tx_action() {
    throw new MethodIsBPFRelatedFunction();
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct net_device"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class net_device extends Struct {
    public char @Size(0) [] __cacheline_group_begin__net_device_read_tx;

    @InlineUnion(3701)
    public anon_member_of_anon_member_of_net_device_and_priv_flags_fast_of_anon_member_of_net_device anon1$0;

    @InlineUnion(3701)
    public anon_member_of_anon_member_of_net_device_and_priv_flags_fast_of_anon_member_of_net_device priv_flags_fast;

    public Ptr<net_device_ops> netdev_ops;

    public Ptr<header_ops> header_ops;

    public Ptr<netdev_queue> _tx;

    public @Unsigned @OriginalName("netdev_features_t") long gso_partial_features;

    public @Unsigned int real_num_tx_queues;

    public @Unsigned int gso_max_size;

    public @Unsigned int gso_ipv4_max_size;

    public @Unsigned short gso_max_segs;

    public short num_tc;

    public @Unsigned int mtu;

    public @Unsigned short needed_headroom;

    public netdev_tc_txq @Size(16) [] tc_to_txq;

    public Ptr<xps_dev_maps> @Size(2) [] xps_maps;

    public Ptr<nf_hook_entries> nf_hooks_egress;

    public Ptr<bpf_mprog_entry> tcx_egress;

    public char @Size(0) [] __cacheline_group_end__net_device_read_tx;

    public char @Size(0) [] __cacheline_group_begin__net_device_read_txrx;

    @InlineUnion(3702)
    public Ptr<pcpu_lstats> lstats;

    @InlineUnion(3702)
    public Ptr<pcpu_sw_netstats> tstats;

    @InlineUnion(3702)
    public Ptr<pcpu_dstats> dstats;

    public @Unsigned long state;

    public @Unsigned int flags;

    public @Unsigned short hard_header_len;

    public @Unsigned @OriginalName("netdev_features_t") long features;

    public Ptr<inet6_dev> ip6_ptr;

    public char @Size(0) [] __cacheline_group_end__net_device_read_txrx;

    public char @Size(0) [] __cacheline_group_begin__net_device_read_rx;

    public Ptr<bpf_prog> xdp_prog;

    public list_head ptype_specific;

    public int ifindex;

    public @Unsigned int real_num_rx_queues;

    public Ptr<netdev_rx_queue> _rx;

    public @Unsigned int gro_max_size;

    public @Unsigned int gro_ipv4_max_size;

    public Ptr<?> rx_handler;

    public Ptr<?> rx_handler_data;

    public possible_net_t nd_net;

    public Ptr<netpoll_info> npinfo;

    public Ptr<bpf_mprog_entry> tcx_ingress;

    public char @Size(0) [] __cacheline_group_end__net_device_read_rx;

    public char @Size(16) [] name;

    public Ptr<netdev_name_node> name_node;

    public Ptr<dev_ifalias> ifalias;

    public @Unsigned long mem_end;

    public @Unsigned long mem_start;

    public @Unsigned long base_addr;

    public list_head dev_list;

    public list_head napi_list;

    public list_head unreg_list;

    public list_head close_list;

    public list_head ptype_all;

    public adj_list_of_net_device adj_list;

    public @Unsigned @OriginalName("xdp_features_t") int xdp_features;

    public Ptr<xdp_metadata_ops> xdp_metadata_ops;

    public Ptr<xsk_tx_metadata_ops> xsk_tx_metadata_ops;

    public @Unsigned short gflags;

    public @Unsigned short needed_tailroom;

    public @Unsigned @OriginalName("netdev_features_t") long hw_features;

    public @Unsigned @OriginalName("netdev_features_t") long wanted_features;

    public @Unsigned @OriginalName("netdev_features_t") long vlan_features;

    public @Unsigned @OriginalName("netdev_features_t") long hw_enc_features;

    public @Unsigned @OriginalName("netdev_features_t") long mpls_features;

    public @Unsigned int min_mtu;

    public @Unsigned int max_mtu;

    public @Unsigned short type;

    public char min_header_len;

    public char name_assign_type;

    public int group;

    public net_device_stats stats;

    public Ptr<net_device_core_stats> core_stats;

    public atomic_t carrier_up_count;

    public atomic_t carrier_down_count;

    public Ptr<iw_handler_def> wireless_handlers;

    public Ptr<ethtool_ops> ethtool_ops;

    public Ptr<l3mdev_ops> l3mdev_ops;

    public Ptr<ndisc_ops> ndisc_ops;

    public Ptr<xfrmdev_ops> xfrmdev_ops;

    public Ptr<tlsdev_ops> tlsdev_ops;

    public @Unsigned int operstate;

    public char link_mode;

    public char if_port;

    public char dma;

    public char @Size(32) [] perm_addr;

    public char addr_assign_type;

    public char addr_len;

    public char upper_level;

    public char lower_level;

    public char threaded;

    public @Unsigned short neigh_priv_len;

    public @Unsigned short dev_id;

    public @Unsigned short dev_port;

    public int irq;

    public @Unsigned int priv_len;

    public @OriginalName("spinlock_t") spinlock addr_list_lock;

    public netdev_hw_addr_list uc;

    public netdev_hw_addr_list mc;

    public netdev_hw_addr_list dev_addrs;

    public Ptr<kset> queues_kset;

    public @Unsigned int promiscuity;

    public @Unsigned int allmulti;

    public boolean uc_promisc;

    public Ptr<in_device> ip_ptr;

    public hlist_head fib_nh_head;

    public Ptr<vlan_info> vlan_info;

    public Ptr<dsa_port> dsa_ptr;

    public @OriginalName("tipc_bearer") Ptr<?> tipc_ptr;

    public Ptr<?> atalk_ptr;

    public Ptr<ax25_dev> ax25_ptr;

    public Ptr<wireless_dev> ieee80211_ptr;

    public Ptr<wpan_dev> ieee802154_ptr;

    public @OriginalName("mpls_dev") Ptr<?> mpls_ptr;

    public Ptr<mctp_dev> mctp_ptr;

    public String dev_addr;

    public @Unsigned int num_rx_queues;

    public @Unsigned int xdp_zc_max_segs;

    public Ptr<netdev_queue> ingress_queue;

    public Ptr<nf_hook_entries> nf_hooks_ingress;

    public char @Size(32) [] broadcast;

    public Ptr<cpu_rmap> rx_cpu_rmap;

    public hlist_node index_hlist;

    public @Unsigned int num_tx_queues;

    public Ptr<Qdisc> qdisc;

    public @Unsigned int tx_queue_len;

    public @OriginalName("spinlock_t") spinlock tx_global_lock;

    public Ptr<xdp_dev_bulk_queue> xdp_bulkq;

    public hlist_head @Size(16) [] qdisc_hash;

    public timer_list watchdog_timer;

    public int watchdog_timeo;

    public @Unsigned int proto_down_reason;

    public list_head todo_list;

    public Ptr<java.lang.Integer> pcpu_refcnt;

    public ref_tracker_dir refcnt_tracker;

    public list_head link_watch_list;

    public char reg_state;

    public boolean dismantle;

    public boolean moving_ns;

    public boolean rtnl_link_initializing;

    public boolean needs_free_netdev;

    public Ptr<?> priv_destructor;

    public Ptr<?> ml_priv;

    public netdev_ml_priv_type ml_priv_type;

    public netdev_stat_type pcpu_stat_type;

    public @OriginalName("garp_port") Ptr<?> garp_port;

    public @OriginalName("mrp_port") Ptr<?> mrp_port;

    public Ptr<dm_hw_stat_delta> dm_private;

    public device dev;

    public Ptr<attribute_group> @Size(5) [] sysfs_groups;

    public Ptr<attribute_group> sysfs_rx_queue_group;

    public Ptr<rtnl_link_ops> rtnl_link_ops;

    public Ptr<netdev_stat_ops> stat_ops;

    public Ptr<netdev_queue_mgmt_ops> queue_mgmt_ops;

    public @Unsigned int tso_max_size;

    public @Unsigned short tso_max_segs;

    public Ptr<dcbnl_rtnl_ops> dcbnl_ops;

    public char @Size(16) [] prio_tc_map;

    public @Unsigned int fcoe_ddp_xid;

    public Ptr<netprio_map> priomap;

    public Ptr<phy_link_topology> link_topo;

    public Ptr<phy_device> phydev;

    public Ptr<sfp_bus> sfp_bus;

    public Ptr<lock_class_key> qdisc_tx_busylock;

    public boolean proto_down;

    public boolean irq_affinity_auto;

    public boolean rx_cpu_rmap_auto;

    public @Unsigned long see_all_hwtstamp_requests;

    public @Unsigned long change_proto_down;

    public @Unsigned long netns_immutable;

    public @Unsigned long fcoe_mtu;

    public list_head net_notifier_list;

    public Ptr<macsec_ops> macsec_ops;

    public Ptr<udp_tunnel_nic_info> udp_tunnel_nic_info;

    public @OriginalName("udp_tunnel_nic") Ptr<?> udp_tunnel_nic;

    public Ptr<netdev_config> cfg;

    public Ptr<netdev_config> cfg_pending;

    public Ptr<ethtool_netdev_state> ethtool;

    public bpf_xdp_entity @Size(3) [] xdp_state;

    public char @Size(32) [] dev_addr_shadow;

    public @OriginalName("netdevice_tracker") lockdep_map_p linkwatch_dev_tracker;

    public @OriginalName("netdevice_tracker") lockdep_map_p watchdog_dev_tracker;

    public @OriginalName("netdevice_tracker") lockdep_map_p dev_registered_tracker;

    public Ptr<rtnl_hw_stats64> offload_xstats_l3;

    public Ptr<devlink_port> devlink_port;

    public Ptr<dpll_pin> dpll_pin;

    public hlist_head page_pools;

    public Ptr<dim_irq_moder> irq_moder;

    public @Unsigned long max_pacing_offload_horizon;

    public Ptr<napi_config> napi_config;

    public @Unsigned int num_napi_configs;

    public @Unsigned int napi_defer_hard_irqs;

    public @Unsigned long gro_flush_timeout;

    public boolean up;

    public boolean request_ops_lock;

    public mutex lock;

    public Ptr<net_shaper_hierarchy> net_shaper_hierarchy;

    public hlist_head @Size(2) [] neighbours;

    public Ptr<hwtstamp_provider> hwprov;

    public char @Size(0) [] priv;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct net_device_stats"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class net_device_stats extends Struct {
    @InlineUnion(3415)
    public @Unsigned long rx_packets;

    @InlineUnion(3415)
    public @OriginalName("atomic_long_t") atomic64_t __rx_packets;

    @InlineUnion(3416)
    public @Unsigned long tx_packets;

    @InlineUnion(3416)
    public @OriginalName("atomic_long_t") atomic64_t __tx_packets;

    @InlineUnion(3417)
    public @Unsigned long rx_bytes;

    @InlineUnion(3417)
    public @OriginalName("atomic_long_t") atomic64_t __rx_bytes;

    @InlineUnion(3418)
    public @Unsigned long tx_bytes;

    @InlineUnion(3418)
    public @OriginalName("atomic_long_t") atomic64_t __tx_bytes;

    @InlineUnion(3419)
    public @Unsigned long rx_errors;

    @InlineUnion(3419)
    public @OriginalName("atomic_long_t") atomic64_t __rx_errors;

    @InlineUnion(3420)
    public @Unsigned long tx_errors;

    @InlineUnion(3420)
    public @OriginalName("atomic_long_t") atomic64_t __tx_errors;

    @InlineUnion(3421)
    public @Unsigned long rx_dropped;

    @InlineUnion(3421)
    public @OriginalName("atomic_long_t") atomic64_t __rx_dropped;

    @InlineUnion(3422)
    public @Unsigned long tx_dropped;

    @InlineUnion(3422)
    public @OriginalName("atomic_long_t") atomic64_t __tx_dropped;

    @InlineUnion(3423)
    public @Unsigned long multicast;

    @InlineUnion(3423)
    public @OriginalName("atomic_long_t") atomic64_t __multicast;

    @InlineUnion(3424)
    public @Unsigned long collisions;

    @InlineUnion(3424)
    public @OriginalName("atomic_long_t") atomic64_t __collisions;

    @InlineUnion(3425)
    public @Unsigned long rx_length_errors;

    @InlineUnion(3425)
    public @OriginalName("atomic_long_t") atomic64_t __rx_length_errors;

    @InlineUnion(3426)
    public @Unsigned long rx_over_errors;

    @InlineUnion(3426)
    public @OriginalName("atomic_long_t") atomic64_t __rx_over_errors;

    @InlineUnion(3427)
    public @Unsigned long rx_crc_errors;

    @InlineUnion(3427)
    public @OriginalName("atomic_long_t") atomic64_t __rx_crc_errors;

    @InlineUnion(3428)
    public @Unsigned long rx_frame_errors;

    @InlineUnion(3428)
    public @OriginalName("atomic_long_t") atomic64_t __rx_frame_errors;

    @InlineUnion(3429)
    public @Unsigned long rx_fifo_errors;

    @InlineUnion(3429)
    public @OriginalName("atomic_long_t") atomic64_t __rx_fifo_errors;

    @InlineUnion(3430)
    public @Unsigned long rx_missed_errors;

    @InlineUnion(3430)
    public @OriginalName("atomic_long_t") atomic64_t __rx_missed_errors;

    @InlineUnion(3431)
    public @Unsigned long tx_aborted_errors;

    @InlineUnion(3431)
    public @OriginalName("atomic_long_t") atomic64_t __tx_aborted_errors;

    @InlineUnion(3432)
    public @Unsigned long tx_carrier_errors;

    @InlineUnion(3432)
    public @OriginalName("atomic_long_t") atomic64_t __tx_carrier_errors;

    @InlineUnion(3433)
    public @Unsigned long tx_fifo_errors;

    @InlineUnion(3433)
    public @OriginalName("atomic_long_t") atomic64_t __tx_fifo_errors;

    @InlineUnion(3434)
    public @Unsigned long tx_heartbeat_errors;

    @InlineUnion(3434)
    public @OriginalName("atomic_long_t") atomic64_t __tx_heartbeat_errors;

    @InlineUnion(3435)
    public @Unsigned long tx_window_errors;

    @InlineUnion(3435)
    public @OriginalName("atomic_long_t") atomic64_t __tx_window_errors;

    @InlineUnion(3436)
    public @Unsigned long rx_compressed;

    @InlineUnion(3436)
    public @OriginalName("atomic_long_t") atomic64_t __rx_compressed;

    @InlineUnion(3437)
    public @Unsigned long tx_compressed;

    @InlineUnion(3437)
    public @OriginalName("atomic_long_t") atomic64_t __tx_compressed;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct net_device_core_stats"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class net_device_core_stats extends Struct {
    public @Unsigned long rx_dropped;

    public @Unsigned long tx_dropped;

    public @Unsigned long rx_nohandler;

    public @Unsigned long rx_otherhost_dropped;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "enum net_device_path_type"
  )
  public enum net_device_path_type implements Enum<net_device_path_type>, TypedEnum<net_device_path_type, java.lang. @Unsigned Integer> {
    /**
     * {@code DEV_PATH_ETHERNET = 0}
     */
    @EnumMember(
        value = 0L,
        name = "DEV_PATH_ETHERNET"
    )
    DEV_PATH_ETHERNET,

    /**
     * {@code DEV_PATH_VLAN = 1}
     */
    @EnumMember(
        value = 1L,
        name = "DEV_PATH_VLAN"
    )
    DEV_PATH_VLAN,

    /**
     * {@code DEV_PATH_BRIDGE = 2}
     */
    @EnumMember(
        value = 2L,
        name = "DEV_PATH_BRIDGE"
    )
    DEV_PATH_BRIDGE,

    /**
     * {@code DEV_PATH_PPPOE = 3}
     */
    @EnumMember(
        value = 3L,
        name = "DEV_PATH_PPPOE"
    )
    DEV_PATH_PPPOE,

    /**
     * {@code DEV_PATH_DSA = 4}
     */
    @EnumMember(
        value = 4L,
        name = "DEV_PATH_DSA"
    )
    DEV_PATH_DSA,

    /**
     * {@code DEV_PATH_MTK_WDMA = 5}
     */
    @EnumMember(
        value = 5L,
        name = "DEV_PATH_MTK_WDMA"
    )
    DEV_PATH_MTK_WDMA
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct net_device_path"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class net_device_path extends Struct {
    public net_device_path_type type;

    public Ptr<net_device> dev;

    @InlineUnion(3494)
    public encap_of_anon_member_of_net_device_path encap;

    @InlineUnion(3494)
    public bridge_of_anon_member_of_net_device_path bridge;

    @InlineUnion(3494)
    public dsa_of_anon_member_of_net_device_path dsa;

    @InlineUnion(3494)
    public mtk_wdma_of_anon_member_of_net_device_path mtk_wdma;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct net_device_path_ctx"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class net_device_path_ctx extends Struct {
    public Ptr<net_device> dev;

    public char @Size(6) [] daddr;

    public int num_vlans;

    public AnonymousType877804870C63 @Size(2) [] vlan;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct net_device_ops"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class net_device_ops extends Struct {
    public Ptr<?> ndo_init;

    public Ptr<?> ndo_uninit;

    public Ptr<?> ndo_open;

    public Ptr<?> ndo_stop;

    public Ptr<?> ndo_start_xmit;

    public Ptr<?> ndo_features_check;

    public Ptr<?> ndo_select_queue;

    public Ptr<?> ndo_change_rx_flags;

    public Ptr<?> ndo_set_rx_mode;

    public Ptr<?> ndo_set_mac_address;

    public Ptr<?> ndo_validate_addr;

    public Ptr<?> ndo_do_ioctl;

    public Ptr<?> ndo_eth_ioctl;

    public Ptr<?> ndo_siocbond;

    public Ptr<?> ndo_siocwandev;

    public Ptr<?> ndo_siocdevprivate;

    public Ptr<?> ndo_set_config;

    public Ptr<?> ndo_change_mtu;

    public Ptr<?> ndo_neigh_setup;

    public Ptr<?> ndo_tx_timeout;

    public Ptr<?> ndo_get_stats64;

    public Ptr<?> ndo_has_offload_stats;

    public Ptr<?> ndo_get_offload_stats;

    public Ptr<?> ndo_get_stats;

    public Ptr<?> ndo_vlan_rx_add_vid;

    public Ptr<?> ndo_vlan_rx_kill_vid;

    public Ptr<?> ndo_poll_controller;

    public Ptr<?> ndo_netpoll_setup;

    public Ptr<?> ndo_netpoll_cleanup;

    public Ptr<?> ndo_set_vf_mac;

    public Ptr<?> ndo_set_vf_vlan;

    public Ptr<?> ndo_set_vf_rate;

    public Ptr<?> ndo_set_vf_spoofchk;

    public Ptr<?> ndo_set_vf_trust;

    public Ptr<?> ndo_get_vf_config;

    public Ptr<?> ndo_set_vf_link_state;

    public Ptr<?> ndo_get_vf_stats;

    public Ptr<?> ndo_set_vf_port;

    public Ptr<?> ndo_get_vf_port;

    public Ptr<?> ndo_get_vf_guid;

    public Ptr<?> ndo_set_vf_guid;

    public Ptr<?> ndo_set_vf_rss_query_en;

    public Ptr<?> ndo_setup_tc;

    public Ptr<?> ndo_fcoe_enable;

    public Ptr<?> ndo_fcoe_disable;

    public Ptr<?> ndo_fcoe_ddp_setup;

    public Ptr<?> ndo_fcoe_ddp_done;

    public Ptr<?> ndo_fcoe_ddp_target;

    public Ptr<?> ndo_fcoe_get_hbainfo;

    public Ptr<?> ndo_fcoe_get_wwn;

    public Ptr<?> ndo_rx_flow_steer;

    public Ptr<?> ndo_add_slave;

    public Ptr<?> ndo_del_slave;

    public Ptr<?> ndo_get_xmit_slave;

    public Ptr<?> ndo_sk_get_lower_dev;

    public Ptr<?> ndo_fix_features;

    public Ptr<?> ndo_set_features;

    public Ptr<?> ndo_neigh_construct;

    public Ptr<?> ndo_neigh_destroy;

    public Ptr<?> ndo_fdb_add;

    public Ptr<?> ndo_fdb_del;

    public Ptr<?> ndo_fdb_del_bulk;

    public Ptr<?> ndo_fdb_dump;

    public Ptr<?> ndo_fdb_get;

    public Ptr<?> ndo_mdb_add;

    public Ptr<?> ndo_mdb_del;

    public Ptr<?> ndo_mdb_del_bulk;

    public Ptr<?> ndo_mdb_dump;

    public Ptr<?> ndo_mdb_get;

    public Ptr<?> ndo_bridge_setlink;

    public Ptr<?> ndo_bridge_getlink;

    public Ptr<?> ndo_bridge_dellink;

    public Ptr<?> ndo_change_carrier;

    public Ptr<?> ndo_get_phys_port_id;

    public Ptr<?> ndo_get_port_parent_id;

    public Ptr<?> ndo_get_phys_port_name;

    public Ptr<?> ndo_dfwd_add_station;

    public Ptr<?> ndo_dfwd_del_station;

    public Ptr<?> ndo_set_tx_maxrate;

    public Ptr<?> ndo_get_iflink;

    public Ptr<?> ndo_fill_metadata_dst;

    public Ptr<?> ndo_set_rx_headroom;

    public Ptr<?> ndo_bpf;

    public Ptr<?> ndo_xdp_xmit;

    public Ptr<?> ndo_xdp_get_xmit_slave;

    public Ptr<?> ndo_xsk_wakeup;

    public Ptr<?> ndo_tunnel_ctl;

    public Ptr<?> ndo_get_peer_dev;

    public Ptr<?> ndo_fill_forward_path;

    public Ptr<?> ndo_get_tstamp;

    public Ptr<?> ndo_hwtstamp_get;

    public Ptr<?> ndo_hwtstamp_set;

    public Ptr<net_shaper_ops> net_shaper_ops;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct net_shaper_ops"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class net_shaper_ops extends Struct {
    public Ptr<?> group;

    public Ptr<?> set;

    public Ptr<?> delete;

    public Ptr<?> capabilities;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct net_generic"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class net_generic extends Struct {
    @InlineUnion(14553)
    public s_of_anon_member_of_net_generic s;

    @InlineUnion(14553)
    public anon_member_of_anon_member_of_net_generic anon0$1;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "enum net_device_flags"
  )
  public enum net_device_flags implements Enum<net_device_flags>, TypedEnum<net_device_flags, java.lang. @Unsigned Integer> {
    /**
     * {@code IFF_UP = 1}
     */
    @EnumMember(
        value = 1L,
        name = "IFF_UP"
    )
    IFF_UP,

    /**
     * {@code IFF_BROADCAST = 2}
     */
    @EnumMember(
        value = 2L,
        name = "IFF_BROADCAST"
    )
    IFF_BROADCAST,

    /**
     * {@code IFF_DEBUG = 4}
     */
    @EnumMember(
        value = 4L,
        name = "IFF_DEBUG"
    )
    IFF_DEBUG,

    /**
     * {@code IFF_LOOPBACK = 8}
     */
    @EnumMember(
        value = 8L,
        name = "IFF_LOOPBACK"
    )
    IFF_LOOPBACK,

    /**
     * {@code IFF_POINTOPOINT = 16}
     */
    @EnumMember(
        value = 16L,
        name = "IFF_POINTOPOINT"
    )
    IFF_POINTOPOINT,

    /**
     * {@code IFF_NOTRAILERS = 32}
     */
    @EnumMember(
        value = 32L,
        name = "IFF_NOTRAILERS"
    )
    IFF_NOTRAILERS,

    /**
     * {@code IFF_RUNNING = 64}
     */
    @EnumMember(
        value = 64L,
        name = "IFF_RUNNING"
    )
    IFF_RUNNING,

    /**
     * {@code IFF_NOARP = 128}
     */
    @EnumMember(
        value = 128L,
        name = "IFF_NOARP"
    )
    IFF_NOARP,

    /**
     * {@code IFF_PROMISC = 256}
     */
    @EnumMember(
        value = 256L,
        name = "IFF_PROMISC"
    )
    IFF_PROMISC,

    /**
     * {@code IFF_ALLMULTI = 512}
     */
    @EnumMember(
        value = 512L,
        name = "IFF_ALLMULTI"
    )
    IFF_ALLMULTI,

    /**
     * {@code IFF_MASTER = 1024}
     */
    @EnumMember(
        value = 1024L,
        name = "IFF_MASTER"
    )
    IFF_MASTER,

    /**
     * {@code IFF_SLAVE = 2048}
     */
    @EnumMember(
        value = 2048L,
        name = "IFF_SLAVE"
    )
    IFF_SLAVE,

    /**
     * {@code IFF_MULTICAST = 4096}
     */
    @EnumMember(
        value = 4096L,
        name = "IFF_MULTICAST"
    )
    IFF_MULTICAST,

    /**
     * {@code IFF_PORTSEL = 8192}
     */
    @EnumMember(
        value = 8192L,
        name = "IFF_PORTSEL"
    )
    IFF_PORTSEL,

    /**
     * {@code IFF_AUTOMEDIA = 16384}
     */
    @EnumMember(
        value = 16384L,
        name = "IFF_AUTOMEDIA"
    )
    IFF_AUTOMEDIA,

    /**
     * {@code IFF_DYNAMIC = 32768}
     */
    @EnumMember(
        value = 32768L,
        name = "IFF_DYNAMIC"
    )
    IFF_DYNAMIC,

    /**
     * {@code IFF_LOWER_UP = 65536}
     */
    @EnumMember(
        value = 65536L,
        name = "IFF_LOWER_UP"
    )
    IFF_LOWER_UP,

    /**
     * {@code IFF_DORMANT = 131072}
     */
    @EnumMember(
        value = 131072L,
        name = "IFF_DORMANT"
    )
    IFF_DORMANT,

    /**
     * {@code IFF_ECHO = 262144}
     */
    @EnumMember(
        value = 262144L,
        name = "IFF_ECHO"
    )
    IFF_ECHO
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct { int type; int protocol; void *addr; int addrlen; struct { void *addr; int addrlen; } peer; }"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class net_of_anon_member_of_anon_member_of_anon_member_of_apparmor_audit_data extends Struct {
    public int type;

    public int protocol;

    public Ptr<?> addr;

    public int addrlen;

    public peer_of_net_of_anon_member_of_anon_member_of_anon_member_of_apparmor_audit_data peer;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "enum net_iov_type"
  )
  public enum net_iov_type implements Enum<net_iov_type>, TypedEnum<net_iov_type, java.lang. @Unsigned Long> {
    /**
     * {@code NET_IOV_DMABUF = 0}
     */
    @EnumMember(
        value = 0L,
        name = "NET_IOV_DMABUF"
    )
    NET_IOV_DMABUF,

    /**
     * {@code NET_IOV_IOURING = 1}
     */
    @EnumMember(
        value = 1L,
        name = "NET_IOV_IOURING"
    )
    NET_IOV_IOURING,

    /**
     * {@code NET_IOV_MAX = -1}
     */
    @EnumMember(
        value = -1L,
        name = "NET_IOV_MAX"
    )
    NET_IOV_MAX
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct net_iov"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class net_iov extends Struct {
    @InlineUnion(32064)
    public netmem_desc desc;

    @InlineUnion(32064)
    public anon_member_of_anon_member_of_net_iov anon0$1;

    public Ptr<net_iov_area> owner;

    public net_iov_type type;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct net_iov_area"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class net_iov_area extends Struct {
    public Ptr<net_iov> niovs;

    public @Unsigned long num_niovs;

    public @Unsigned long base_virtual;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct net_protocol"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class net_protocol extends Struct {
    public Ptr<?> handler;

    public Ptr<?> err_handler;

    public @Unsigned int no_policy;

    public @Unsigned int icmp_strict_tag_validation;

    public @Unsigned int secret;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct net_offload"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class net_offload extends Struct {
    public offload_callbacks callbacks;

    public @Unsigned int flags;

    public @Unsigned int secret;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct net_hotdata"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class net_hotdata extends Struct {
    public packet_offload ip_packet_offload;

    public net_offload tcpv4_offload;

    public net_protocol tcp_protocol;

    public net_offload udpv4_offload;

    public net_protocol udp_protocol;

    public packet_offload ipv6_packet_offload;

    public net_offload tcpv6_offload;

    public inet6_protocol tcpv6_protocol;

    public inet6_protocol udpv6_protocol;

    public net_offload udpv6_offload;

    public list_head offload_base;

    public Ptr<kmem_cache> skbuff_cache;

    public Ptr<kmem_cache> skbuff_fclone_cache;

    public Ptr<kmem_cache> skb_small_head_cache;

    public Ptr<rps_sock_flow_table> rps_sock_flow_table;

    public @Unsigned int rps_cpu_mask;

    public int gro_normal_batch;

    public int netdev_budget;

    public int netdev_budget_usecs;

    public int tstamp_prequeue;

    public int max_backlog;

    public int dev_tx_weight;

    public int dev_rx_weight;

    public int sysctl_max_skb_frags;

    public int sysctl_skb_defer_max;

    public int sysctl_mem_pcpu_rsv;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct net_failover_info"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class net_failover_info extends Struct {
    public Ptr<net_device> primary_dev;

    public Ptr<net_device> standby_dev;

    public rtnl_link_stats64 primary_stats;

    public rtnl_link_stats64 standby_stats;

    public rtnl_link_stats64 failover_stats;

    public @OriginalName("spinlock_t") spinlock stats_lock;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct net_device_devres"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class net_device_devres extends Struct {
    public Ptr<net_device> ndev;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct net_proto_family"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class net_proto_family extends Struct {
    public int family;

    public Ptr<?> create;

    public Ptr<module> owner;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct net_devmem_dmabuf_binding"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class net_devmem_dmabuf_binding extends Struct {
    public Ptr<dma_buf> dmabuf;

    public Ptr<dma_buf_attachment> attachment;

    public Ptr<sg_table> sgt;

    public Ptr<net_device> dev;

    public Ptr<gen_pool> chunk_pool;

    public mutex lock;

    public @OriginalName("refcount_t") refcount_struct ref;

    public list_head list;

    public xarray bound_rxqs;

    public @Unsigned int id;

    public dma_data_direction direction;

    public Ptr<Ptr<net_iov>> tx_vec;

    public work_struct unbind_w;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct net_rate_estimator"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class net_rate_estimator extends Struct {
    public Ptr<gnet_stats_basic_sync> bstats;

    public Ptr<@OriginalName("spinlock_t") spinlock> stats_lock;

    public boolean running;

    public Ptr<gnet_stats_basic_sync> cpu_bstats;

    public char ewma_log;

    public char intvl_log;

    public @OriginalName("seqcount_t") seqcount seq;

    public @Unsigned long last_packets;

    public @Unsigned long last_bytes;

    public @Unsigned long avpps;

    public @Unsigned long avbps;

    public @Unsigned long next_jiffies;

    public timer_list timer;

    public callback_head rcu;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct net_aligned_data"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class net_aligned_data extends Struct {
    public atomic64_t net_cookie;

    public @OriginalName("atomic_long_t") atomic64_t tcp_memory_allocated;

    public @OriginalName("atomic_long_t") atomic64_t udp_memory_allocated;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct net_fill_args"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class net_fill_args extends Struct {
    public @Unsigned int portid;

    public @Unsigned int seq;

    public int flags;

    public int cmd;

    public int nsid;

    public boolean add_ref;

    public int ref_nsid;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct net_device_path_stack"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class net_device_path_stack extends Struct {
    public int num_paths;

    public net_device_path @Size(5) [] path;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct net_bridge"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class net_bridge extends Struct {
    public @OriginalName("spinlock_t") spinlock lock;

    public @OriginalName("spinlock_t") spinlock hash_lock;

    public hlist_head frame_type_list;

    public Ptr<net_device> dev;

    public @Unsigned long options;

    public @Unsigned @OriginalName("__be16") short vlan_proto;

    public @Unsigned short default_pvid;

    public Ptr<net_bridge_vlan_group> vlgrp;

    public rhashtable fdb_hash_tbl;

    public list_head port_list;

    @InlineUnion(59928)
    public rtable fake_rtable;

    @InlineUnion(59928)
    public rt6_info fake_rt6_info;

    public @Unsigned int @Size(17) [] metrics;

    public @Unsigned short group_fwd_mask;

    public @Unsigned short group_fwd_mask_required;

    public bridge_id designated_root;

    public bridge_id bridge_id;

    public char topology_change;

    public char topology_change_detected;

    public @Unsigned short root_port;

    public @Unsigned long max_age;

    public @Unsigned long hello_time;

    public @Unsigned long forward_delay;

    public @Unsigned long ageing_time;

    public @Unsigned long bridge_max_age;

    public @Unsigned long bridge_hello_time;

    public @Unsigned long bridge_forward_delay;

    public @Unsigned long bridge_ageing_time;

    public @Unsigned int root_path_cost;

    public char @Size(6) [] group_addr;

    public stp_enabled_of_net_bridge stp_enabled;

    public net_bridge_mcast multicast_ctx;

    public Ptr<bridge_mcast_stats> mcast_stats;

    public @Unsigned int hash_max;

    public @OriginalName("spinlock_t") spinlock multicast_lock;

    public rhashtable mdb_hash_tbl;

    public rhashtable sg_port_tbl;

    public hlist_head mcast_gc_list;

    public hlist_head mdb_list;

    public work_struct mcast_gc_work;

    public timer_list hello_timer;

    public timer_list tcn_timer;

    public timer_list topology_change_timer;

    public delayed_work gc_work;

    public Ptr<kobject> ifobj;

    public @Unsigned int auto_cnt;

    public atomic_t fdb_n_learned;

    public @Unsigned int fdb_max_learned;

    public int last_hwdom;

    public @Unsigned long busy_hwdoms;

    public hlist_head fdb_list;

    public hlist_head mrp_list;

    public hlist_head mep_list;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct net_bridge_port"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class net_bridge_port extends Struct {
    public Ptr<net_bridge> br;

    public Ptr<net_device> dev;

    public @OriginalName("netdevice_tracker") lockdep_map_p dev_tracker;

    public list_head list;

    public @Unsigned long flags;

    public Ptr<net_bridge_vlan_group> vlgrp;

    public Ptr<net_bridge_port> backup_port;

    public @Unsigned int backup_nhid;

    public char priority;

    public char state;

    public @Unsigned short port_no;

    public char topology_change_ack;

    public char config_pending;

    public @Unsigned @OriginalName("port_id") short port_id;

    public @Unsigned @OriginalName("port_id") short designated_port;

    public bridge_id designated_root;

    public bridge_id designated_bridge;

    public @Unsigned int path_cost;

    public @Unsigned int designated_cost;

    public @Unsigned long designated_age;

    public timer_list forward_delay_timer;

    public timer_list hold_timer;

    public timer_list message_age_timer;

    public kobject kobj;

    public callback_head rcu;

    public net_bridge_mcast_port multicast_ctx;

    public Ptr<bridge_mcast_stats> mcast_stats;

    public @Unsigned int multicast_eht_hosts_limit;

    public @Unsigned int multicast_eht_hosts_cnt;

    public hlist_head mglist;

    public char @Size(16) [] sysfs_name;

    public Ptr<netpoll> np;

    public int hwdom;

    public int offload_count;

    public netdev_phys_item_id ppid;

    public @Unsigned short group_fwd_mask;

    public @Unsigned short backup_redirected_cnt;

    public bridge_stp_xstats stp_xstats;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct net_bridge_mcast_port"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class net_bridge_mcast_port extends Struct {
    public Ptr<net_bridge_port> port;

    public Ptr<net_bridge_vlan> vlan;

    public bridge_mcast_own_query ip4_own_query;

    public timer_list ip4_mc_router_timer;

    public hlist_node ip4_rlist;

    public bridge_mcast_own_query ip6_own_query;

    public timer_list ip6_mc_router_timer;

    public hlist_node ip6_rlist;

    public char multicast_router;

    public @Unsigned int mdb_n_entries;

    public @Unsigned int mdb_max_entries;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct net_bridge_vlan"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class net_bridge_vlan extends Struct {
    public rhash_head vnode;

    public rhash_head tnode;

    public @Unsigned short vid;

    public @Unsigned short flags;

    public @Unsigned short priv_flags;

    public char state;

    public Ptr<pcpu_sw_netstats> stats;

    @InlineUnion(59920)
    public Ptr<net_bridge> br;

    @InlineUnion(59920)
    public Ptr<net_bridge_port> port;

    @InlineUnion(59921)
    public @OriginalName("refcount_t") refcount_struct refcnt;

    @InlineUnion(59921)
    public Ptr<net_bridge_vlan> brvlan;

    public br_tunnel_info tinfo;

    @InlineUnion(59922)
    public net_bridge_mcast br_mcast_ctx;

    @InlineUnion(59922)
    public net_bridge_mcast_port port_mcast_ctx;

    public @Unsigned short msti;

    public list_head vlist;

    public callback_head rcu;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct net_bridge_mcast"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class net_bridge_mcast extends Struct {
    public Ptr<net_bridge> br;

    public Ptr<net_bridge_vlan> vlan;

    public @Unsigned int multicast_last_member_count;

    public @Unsigned int multicast_startup_query_count;

    public char multicast_querier;

    public char multicast_igmp_version;

    public char multicast_router;

    public char multicast_mld_version;

    public @Unsigned long multicast_last_member_interval;

    public @Unsigned long multicast_membership_interval;

    public @Unsigned long multicast_querier_interval;

    public @Unsigned long multicast_query_interval;

    public @Unsigned long multicast_query_response_interval;

    public @Unsigned long multicast_startup_query_interval;

    public hlist_head ip4_mc_router_list;

    public timer_list ip4_mc_router_timer;

    public bridge_mcast_other_query ip4_other_query;

    public bridge_mcast_own_query ip4_own_query;

    public bridge_mcast_querier ip4_querier;

    public hlist_head ip6_mc_router_list;

    public timer_list ip6_mc_router_timer;

    public bridge_mcast_other_query ip6_other_query;

    public bridge_mcast_own_query ip6_own_query;

    public bridge_mcast_querier ip6_querier;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct net_bridge_vlan_group"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class net_bridge_vlan_group extends Struct {
    public rhashtable vlan_hash;

    public rhashtable tunnel_hash;

    public list_head vlan_list;

    public @Unsigned short num_vlans;

    public @Unsigned short pvid;

    public char pvid_state;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct net_bridge_fdb_key"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class net_bridge_fdb_key extends Struct {
    public mac_addr addr;

    public @Unsigned short vlan_id;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct net_bridge_fdb_entry"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class net_bridge_fdb_entry extends Struct {
    public rhash_head rhnode;

    public Ptr<net_bridge_port> dst;

    public net_bridge_fdb_key key;

    public hlist_node fdb_node;

    public @Unsigned long flags;

    public @Unsigned long updated;

    public @Unsigned long used;

    public callback_head rcu;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct net_dm_drop_point"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class net_dm_drop_point extends Struct {
    public char @Size(8) [] pc;

    public @Unsigned int count;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct net_dm_alert_msg"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class net_dm_alert_msg extends Struct {
    public @Unsigned int entries;

    public net_dm_drop_point @Size(0) [] points;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "enum net_dm_attr"
  )
  public enum net_dm_attr implements Enum<net_dm_attr>, TypedEnum<net_dm_attr, java.lang. @Unsigned Integer> {
    /**
     * {@code NET_DM_ATTR_UNSPEC = 0}
     */
    @EnumMember(
        value = 0L,
        name = "NET_DM_ATTR_UNSPEC"
    )
    NET_DM_ATTR_UNSPEC,

    /**
     * {@code NET_DM_ATTR_ALERT_MODE = 1}
     */
    @EnumMember(
        value = 1L,
        name = "NET_DM_ATTR_ALERT_MODE"
    )
    NET_DM_ATTR_ALERT_MODE,

    /**
     * {@code NET_DM_ATTR_PC = 2}
     */
    @EnumMember(
        value = 2L,
        name = "NET_DM_ATTR_PC"
    )
    NET_DM_ATTR_PC,

    /**
     * {@code NET_DM_ATTR_SYMBOL = 3}
     */
    @EnumMember(
        value = 3L,
        name = "NET_DM_ATTR_SYMBOL"
    )
    NET_DM_ATTR_SYMBOL,

    /**
     * {@code NET_DM_ATTR_IN_PORT = 4}
     */
    @EnumMember(
        value = 4L,
        name = "NET_DM_ATTR_IN_PORT"
    )
    NET_DM_ATTR_IN_PORT,

    /**
     * {@code NET_DM_ATTR_TIMESTAMP = 5}
     */
    @EnumMember(
        value = 5L,
        name = "NET_DM_ATTR_TIMESTAMP"
    )
    NET_DM_ATTR_TIMESTAMP,

    /**
     * {@code NET_DM_ATTR_PROTO = 6}
     */
    @EnumMember(
        value = 6L,
        name = "NET_DM_ATTR_PROTO"
    )
    NET_DM_ATTR_PROTO,

    /**
     * {@code NET_DM_ATTR_PAYLOAD = 7}
     */
    @EnumMember(
        value = 7L,
        name = "NET_DM_ATTR_PAYLOAD"
    )
    NET_DM_ATTR_PAYLOAD,

    /**
     * {@code NET_DM_ATTR_PAD = 8}
     */
    @EnumMember(
        value = 8L,
        name = "NET_DM_ATTR_PAD"
    )
    NET_DM_ATTR_PAD,

    /**
     * {@code NET_DM_ATTR_TRUNC_LEN = 9}
     */
    @EnumMember(
        value = 9L,
        name = "NET_DM_ATTR_TRUNC_LEN"
    )
    NET_DM_ATTR_TRUNC_LEN,

    /**
     * {@code NET_DM_ATTR_ORIG_LEN = 10}
     */
    @EnumMember(
        value = 10L,
        name = "NET_DM_ATTR_ORIG_LEN"
    )
    NET_DM_ATTR_ORIG_LEN,

    /**
     * {@code NET_DM_ATTR_QUEUE_LEN = 11}
     */
    @EnumMember(
        value = 11L,
        name = "NET_DM_ATTR_QUEUE_LEN"
    )
    NET_DM_ATTR_QUEUE_LEN,

    /**
     * {@code NET_DM_ATTR_STATS = 12}
     */
    @EnumMember(
        value = 12L,
        name = "NET_DM_ATTR_STATS"
    )
    NET_DM_ATTR_STATS,

    /**
     * {@code NET_DM_ATTR_HW_STATS = 13}
     */
    @EnumMember(
        value = 13L,
        name = "NET_DM_ATTR_HW_STATS"
    )
    NET_DM_ATTR_HW_STATS,

    /**
     * {@code NET_DM_ATTR_ORIGIN = 14}
     */
    @EnumMember(
        value = 14L,
        name = "NET_DM_ATTR_ORIGIN"
    )
    NET_DM_ATTR_ORIGIN,

    /**
     * {@code NET_DM_ATTR_HW_TRAP_GROUP_NAME = 15}
     */
    @EnumMember(
        value = 15L,
        name = "NET_DM_ATTR_HW_TRAP_GROUP_NAME"
    )
    NET_DM_ATTR_HW_TRAP_GROUP_NAME,

    /**
     * {@code NET_DM_ATTR_HW_TRAP_NAME = 16}
     */
    @EnumMember(
        value = 16L,
        name = "NET_DM_ATTR_HW_TRAP_NAME"
    )
    NET_DM_ATTR_HW_TRAP_NAME,

    /**
     * {@code NET_DM_ATTR_HW_ENTRIES = 17}
     */
    @EnumMember(
        value = 17L,
        name = "NET_DM_ATTR_HW_ENTRIES"
    )
    NET_DM_ATTR_HW_ENTRIES,

    /**
     * {@code NET_DM_ATTR_HW_ENTRY = 18}
     */
    @EnumMember(
        value = 18L,
        name = "NET_DM_ATTR_HW_ENTRY"
    )
    NET_DM_ATTR_HW_ENTRY,

    /**
     * {@code NET_DM_ATTR_HW_TRAP_COUNT = 19}
     */
    @EnumMember(
        value = 19L,
        name = "NET_DM_ATTR_HW_TRAP_COUNT"
    )
    NET_DM_ATTR_HW_TRAP_COUNT,

    /**
     * {@code NET_DM_ATTR_SW_DROPS = 20}
     */
    @EnumMember(
        value = 20L,
        name = "NET_DM_ATTR_SW_DROPS"
    )
    NET_DM_ATTR_SW_DROPS,

    /**
     * {@code NET_DM_ATTR_HW_DROPS = 21}
     */
    @EnumMember(
        value = 21L,
        name = "NET_DM_ATTR_HW_DROPS"
    )
    NET_DM_ATTR_HW_DROPS,

    /**
     * {@code NET_DM_ATTR_FLOW_ACTION_COOKIE = 22}
     */
    @EnumMember(
        value = 22L,
        name = "NET_DM_ATTR_FLOW_ACTION_COOKIE"
    )
    NET_DM_ATTR_FLOW_ACTION_COOKIE,

    /**
     * {@code NET_DM_ATTR_REASON = 23}
     */
    @EnumMember(
        value = 23L,
        name = "NET_DM_ATTR_REASON"
    )
    NET_DM_ATTR_REASON,

    /**
     * {@code __NET_DM_ATTR_MAX = 24}
     */
    @EnumMember(
        value = 24L,
        name = "__NET_DM_ATTR_MAX"
    )
    __NET_DM_ATTR_MAX,

    /**
     * {@code NET_DM_ATTR_MAX = 23}
     */
    @EnumMember(
        value = 23L,
        name = "NET_DM_ATTR_MAX"
    )
    NET_DM_ATTR_MAX
  }

  @Type(
      noCCodeGeneration = true,
      cType = "enum net_dm_alert_mode"
  )
  public enum net_dm_alert_mode implements Enum<net_dm_alert_mode>, TypedEnum<net_dm_alert_mode, java.lang. @Unsigned Integer> {
    /**
     * {@code NET_DM_ALERT_MODE_SUMMARY = 0}
     */
    @EnumMember(
        value = 0L,
        name = "NET_DM_ALERT_MODE_SUMMARY"
    )
    NET_DM_ALERT_MODE_SUMMARY,

    /**
     * {@code NET_DM_ALERT_MODE_PACKET = 1}
     */
    @EnumMember(
        value = 1L,
        name = "NET_DM_ALERT_MODE_PACKET"
    )
    NET_DM_ALERT_MODE_PACKET
  }

  @Type(
      noCCodeGeneration = true,
      cType = "enum net_dm_origin"
  )
  public enum net_dm_origin implements Enum<net_dm_origin>, TypedEnum<net_dm_origin, java.lang. @Unsigned Integer> {
    /**
     * {@code NET_DM_ORIGIN_SW = 0}
     */
    @EnumMember(
        value = 0L,
        name = "NET_DM_ORIGIN_SW"
    )
    NET_DM_ORIGIN_SW,

    /**
     * {@code NET_DM_ORIGIN_HW = 1}
     */
    @EnumMember(
        value = 1L,
        name = "NET_DM_ORIGIN_HW"
    )
    NET_DM_ORIGIN_HW
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct net_dm_stats"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class net_dm_stats extends Struct {
    public u64_stats_t dropped;

    public u64_stats_sync syncp;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct net_dm_hw_entry"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class net_dm_hw_entry extends Struct {
    public char @Size(40) [] trap_name;

    public @Unsigned int count;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct net_dm_hw_entries"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class net_dm_hw_entries extends Struct {
    public @Unsigned int num_entries;

    public net_dm_hw_entry @Size(0) [] entries;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct net_dm_alert_ops"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class net_dm_alert_ops extends Struct {
    public Ptr<?> kfree_skb_probe;

    public Ptr<?> napi_poll_probe;

    public Ptr<?> work_item_func;

    public Ptr<?> hw_work_item_func;

    public Ptr<?> hw_trap_probe;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct net_dm_skb_cb"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class net_dm_skb_cb extends Struct {
    @InlineUnion(60173)
    public Ptr<devlink_trap_metadata> hw_metadata;

    @InlineUnion(60173)
    public Ptr<?> pc;

    public skb_drop_reason reason;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct net_packet_attrs"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class net_packet_attrs extends Struct {
    public String src;

    public String dst;

    public @Unsigned int ip_src;

    public @Unsigned int ip_dst;

    public boolean tcp;

    public @Unsigned short sport;

    public @Unsigned short dport;

    public int timeout;

    public int size;

    public int max_size;

    public char id;

    public @Unsigned short queue_mapping;

    public boolean bad_csum;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct net_test_priv"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class net_test_priv extends Struct {
    public Ptr<net_packet_attrs> packet;

    public packet_type pt;

    public completion comp;

    public int double_vlan;

    public int vlan_id;

    public int ok;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct net_test"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class net_test extends Struct {
    public char @Size(32) [] name;

    public Ptr<?> fn;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "enum net_xmit_qdisc_t"
  )
  public enum net_xmit_qdisc_t implements Enum<net_xmit_qdisc_t>, TypedEnum<net_xmit_qdisc_t, java.lang. @Unsigned Integer> {
    /**
     * {@code __NET_XMIT_STOLEN = 65536}
     */
    @EnumMember(
        value = 65536L,
        name = "__NET_XMIT_STOLEN"
    )
    __NET_XMIT_STOLEN,

    /**
     * {@code __NET_XMIT_BYPASS = 131072}
     */
    @EnumMember(
        value = 131072L,
        name = "__NET_XMIT_BYPASS"
    )
    __NET_XMIT_BYPASS
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct net_shaper_hierarchy"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class net_shaper_hierarchy extends Struct {
    public xarray shapers;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "enum net_shaper_scope"
  )
  public enum net_shaper_scope implements Enum<net_shaper_scope>, TypedEnum<net_shaper_scope, java.lang. @Unsigned Integer> {
    /**
     * {@code NET_SHAPER_SCOPE_UNSPEC = 0}
     */
    @EnumMember(
        value = 0L,
        name = "NET_SHAPER_SCOPE_UNSPEC"
    )
    NET_SHAPER_SCOPE_UNSPEC,

    /**
     * {@code NET_SHAPER_SCOPE_NETDEV = 1}
     */
    @EnumMember(
        value = 1L,
        name = "NET_SHAPER_SCOPE_NETDEV"
    )
    NET_SHAPER_SCOPE_NETDEV,

    /**
     * {@code NET_SHAPER_SCOPE_QUEUE = 2}
     */
    @EnumMember(
        value = 2L,
        name = "NET_SHAPER_SCOPE_QUEUE"
    )
    NET_SHAPER_SCOPE_QUEUE,

    /**
     * {@code NET_SHAPER_SCOPE_NODE = 3}
     */
    @EnumMember(
        value = 3L,
        name = "NET_SHAPER_SCOPE_NODE"
    )
    NET_SHAPER_SCOPE_NODE,

    /**
     * {@code __NET_SHAPER_SCOPE_MAX = 4}
     */
    @EnumMember(
        value = 4L,
        name = "__NET_SHAPER_SCOPE_MAX"
    )
    __NET_SHAPER_SCOPE_MAX,

    /**
     * {@code NET_SHAPER_SCOPE_MAX = 3}
     */
    @EnumMember(
        value = 3L,
        name = "NET_SHAPER_SCOPE_MAX"
    )
    NET_SHAPER_SCOPE_MAX
  }

  @Type(
      noCCodeGeneration = true,
      cType = "enum net_shaper_metric"
  )
  public enum net_shaper_metric implements Enum<net_shaper_metric>, TypedEnum<net_shaper_metric, java.lang. @Unsigned Integer> {
    /**
     * {@code NET_SHAPER_METRIC_BPS = 0}
     */
    @EnumMember(
        value = 0L,
        name = "NET_SHAPER_METRIC_BPS"
    )
    NET_SHAPER_METRIC_BPS,

    /**
     * {@code NET_SHAPER_METRIC_PPS = 1}
     */
    @EnumMember(
        value = 1L,
        name = "NET_SHAPER_METRIC_PPS"
    )
    NET_SHAPER_METRIC_PPS
  }

  @Type(
      noCCodeGeneration = true,
      cType = "enum net_shaper_binding_type"
  )
  public enum net_shaper_binding_type implements Enum<net_shaper_binding_type>, TypedEnum<net_shaper_binding_type, java.lang. @Unsigned Integer> {
    /**
     * {@code NET_SHAPER_BINDING_TYPE_NETDEV = 0}
     */
    @EnumMember(
        value = 0L,
        name = "NET_SHAPER_BINDING_TYPE_NETDEV"
    )
    NET_SHAPER_BINDING_TYPE_NETDEV
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct net_shaper_binding"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class net_shaper_binding extends Struct {
    public net_shaper_binding_type type;

    @InlineUnion(65316)
    public Ptr<net_device> netdev;

    @InlineUnion(65316)
    public Ptr<devlink> devlink;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct net_shaper_handle"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class net_shaper_handle extends Struct {
    public net_shaper_scope scope;

    public @Unsigned int id;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct net_shaper"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class net_shaper extends Struct {
    public net_shaper_handle parent;

    public net_shaper_handle handle;

    public net_shaper_metric metric;

    public @Unsigned long bw_min;

    public @Unsigned long bw_max;

    public @Unsigned long burst;

    public @Unsigned int priority;

    public @Unsigned int weight;

    public @Unsigned int leaves;

    public callback_head rcu;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct net_shaper_nl_ctx"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class net_shaper_nl_ctx extends Struct {
    public net_shaper_binding binding;

    public @OriginalName("netdevice_tracker") lockdep_map_p dev_tracker;

    public @Unsigned long start_index;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct { short unsigned int id; short unsigned int proto; }"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class AnonymousType877804870C63 extends Struct {
    public @Unsigned short id;

    public @Unsigned @OriginalName("__be16") short proto;
  }
}
