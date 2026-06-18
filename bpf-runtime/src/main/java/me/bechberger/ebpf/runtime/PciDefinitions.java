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
 * Generated class for BPF runtime types that start with pci
 */
@java.lang.SuppressWarnings("unused")
public final class PciDefinitions {
  public static final @Unsigned int pci_channel_io_normal = 1;

  public static final @Unsigned int pci_channel_io_frozen = 2;

  public static final @Unsigned int pci_channel_io_perm_failure = 3;

  @NotUsableInJava
  @BuiltinBPFFunction("__pci_bridge_assign_resources((const struct pci_dev*)$arg1, $arg2, $arg3)")
  public static void __pci_bridge_assign_resources(Ptr<pci_dev> bridge, Ptr<list_head> add_head,
      Ptr<list_head> fail_head) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("__pci_bus_assign_resources((const struct pci_bus*)$arg1, $arg2, $arg3)")
  public static void __pci_bus_assign_resources(Ptr<pci_bus> bus, Ptr<list_head> realloc_head,
      Ptr<list_head> fail_head) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __pci_bus_size_bridges(Ptr<pci_bus> bus, Ptr<list_head> realloc_head) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("__pci_config_acs($arg1, $arg2, (const u8*)$arg3, (const short unsigned int)$arg4, (const short unsigned int)$arg5)")
  public static void __pci_config_acs(Ptr<pci_dev> dev, Ptr<pci_acs> caps, String p,
      @Unsigned short acs_mask, @Unsigned short acs_flags) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int __pci_dev_set_current_state(Ptr<pci_dev> dev, Ptr<?> data) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int __pci_disable_link_state(Ptr<pci_dev> pdev, int state, boolean locked) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int __pci_enable_link_state(Ptr<pci_dev> pdev, int state, boolean locked) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int __pci_enable_msi_range(Ptr<pci_dev> dev, int minvec, int maxvec,
      Ptr<irq_affinity> affd) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int __pci_enable_msix_range(Ptr<pci_dev> dev, Ptr<msix_entry> entries, int minvec,
      int maxvec, Ptr<irq_affinity> affd, int flags) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int __pci_enable_ptm(Ptr<pci_dev> dev) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int __pci_enable_wake(Ptr<pci_dev> dev, @OriginalName("pci_power_t") int state,
      boolean enable) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("__pci_epc_create($arg1, (const struct pci_epc_ops*)$arg2, $arg3)")
  public static Ptr<pci_epc> __pci_epc_create(Ptr<device> dev, Ptr<pci_epc_ops> ops,
      Ptr<module> owner) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int __pci_epf_register_driver(Ptr<pci_epf_driver> driver, Ptr<module> owner) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static char __pci_find_next_cap_ttl(Ptr<pci_bus> bus, @Unsigned int devfn, char pos,
      int cap, Ptr<java.lang.Integer> ttl) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static char __pci_find_next_ht_cap(Ptr<pci_dev> dev, char pos, int ht_cap) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("__pci_hp_initialize($arg1, $arg2, $arg3, (const u8*)$arg4, $arg5, (const u8*)$arg6)")
  public static int __pci_hp_initialize(Ptr<hotplug_slot> slot, Ptr<pci_bus> bus, int devnr,
      String name, Ptr<module> owner, String mod_name) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("__pci_hp_register($arg1, $arg2, $arg3, (const u8*)$arg4, $arg5, (const u8*)$arg6)")
  public static int __pci_hp_register(Ptr<hotplug_slot> slot, Ptr<pci_bus> bus, int devnr,
      String name, Ptr<module> owner, String mod_name) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __pci_mmcfg_init(int early) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __pci_p2pdma_update_state(Ptr<pci_p2pdma_map_state> state, Ptr<device> dev,
      Ptr<page> page) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __pci_pme_active(Ptr<pci_dev> dev, boolean enable) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int __pci_read_base(Ptr<pci_dev> dev, pci_bar_type type, Ptr<resource> res,
      @Unsigned int pos, Ptr<java.lang. @Unsigned Integer> sizes) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __pci_read_msi_msg(Ptr<msi_desc> entry, Ptr<msi_msg> msg) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static @OriginalName("ssize_t") long __pci_read_vpd(Ptr<pci_dev> dev,
      @OriginalName("loff_t") long pos, @Unsigned long count, Ptr<?> buf, boolean check_size) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("__pci_register_driver($arg1, $arg2, (const u8*)$arg3)")
  public static int __pci_register_driver(Ptr<pci_driver> drv, Ptr<module> owner, String mod_name) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("__pci_request_region($arg1, $arg2, (const u8*)$arg3, $arg4)")
  public static int __pci_request_region(Ptr<pci_dev> pdev, int bar, String name, int exclusive) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("__pci_request_selected_regions($arg1, $arg2, (const u8*)$arg3, $arg4)")
  public static int __pci_request_selected_regions(Ptr<pci_dev> pdev, int bars, String name,
      int excl) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int __pci_reset_bus(Ptr<pci_bus> bus) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int __pci_reset_function_locked(Ptr<pci_dev> dev) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int __pci_reset_slot(Ptr<pci_slot> slot) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __pci_restore_msi_state(Ptr<pci_dev> dev) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __pci_restore_msix_state(Ptr<pci_dev> dev) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __pci_set_master(Ptr<pci_dev> dev, boolean enable) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int __pci_set_power_state(Ptr<pci_dev> dev, @OriginalName("pci_power_t") int state,
      boolean locked) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __pci_setup_bridge(Ptr<pci_bus> bus, @Unsigned long type) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __pci_size_bars(Ptr<pci_dev> dev, int count, @Unsigned int pos,
      Ptr<java.lang. @Unsigned Integer> sizes, boolean rom) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __pci_size_stdbars(Ptr<pci_dev> dev, int count, @Unsigned int pos,
      Ptr<java.lang. @Unsigned Integer> sizes) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("__pci_walk_bus($arg1, (int (*)(struct pci_dev*, void*))$arg2, $arg3)")
  public static int __pci_walk_bus(Ptr<pci_bus> top, Ptr<?> cb, Ptr<?> userdata) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __pci_write_msi_msg(Ptr<msi_desc> entry, Ptr<msi_msg> msg) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("__pci_write_vpd($arg1, $arg2, $arg3, (const void*)$arg4, $arg5)")
  public static @OriginalName("ssize_t") long __pci_write_vpd(Ptr<pci_dev> dev,
      @OriginalName("loff_t") long pos, @Unsigned long count, Ptr<?> buf, boolean check_size) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int _pci_add_cap_save_buffer(Ptr<pci_dev> dev, @Unsigned short cap,
      boolean extended, @Unsigned int size) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int _pci_assign_resource(Ptr<pci_dev> dev, int resno,
      @Unsigned @OriginalName("resource_size_t") long size,
      @Unsigned @OriginalName("resource_size_t") long min_align) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static @Unsigned @OriginalName("acpi_status") int pci_acpi_add_bus_pm_notifier(
      Ptr<acpi_device> dev) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void pci_acpi_add_edr_notifier(Ptr<pci_dev> pdev) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static @Unsigned @OriginalName("acpi_status") int pci_acpi_add_pm_notifier(
      Ptr<acpi_device> dev, Ptr<pci_dev> pci_dev) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void pci_acpi_cleanup(Ptr<device> dev, Ptr<acpi_device> adev) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void pci_acpi_clear_companion_lookup_hook() {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void pci_acpi_crs_quirks() {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int pci_acpi_init() {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static boolean pci_acpi_preserve_config(Ptr<pci_host_bridge> host_bridge) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int pci_acpi_program_hp_params(Ptr<pci_dev> dev) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void pci_acpi_remove_edr_notifier(Ptr<pci_dev> pdev) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int pci_acpi_root_init_info(Ptr<acpi_pci_root_info> ci) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int pci_acpi_root_prepare_resources(Ptr<acpi_pci_root_info> ci) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void pci_acpi_root_release_info(Ptr<acpi_pci_root_info> ci) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static Ptr<pci_bus> pci_acpi_scan_root(Ptr<acpi_pci_root> root) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("pci_acpi_set_companion_lookup_hook((struct acpi_device* (*)(struct pci_dev*))$arg1)")
  public static int pci_acpi_set_companion_lookup_hook(Ptr<?> func) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void pci_acpi_setup(Ptr<device> dev, Ptr<acpi_device> adev) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void pci_acpi_wake_bus(Ptr<acpi_device_wakeup_context> context) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void pci_acpi_wake_dev(Ptr<acpi_device_wakeup_context> context) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static boolean pci_acs_enabled(Ptr<pci_dev> pdev, @Unsigned short acs_flags) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static boolean pci_acs_flags_enabled(Ptr<pci_dev> pdev, @Unsigned short acs_flags) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void pci_acs_init(Ptr<pci_dev> dev) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static boolean pci_acs_path_enabled(Ptr<pci_dev> start, Ptr<pci_dev> end,
      @Unsigned short acs_flags) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int pci_add_cap_save_buffer(Ptr<pci_dev> dev, char cap, @Unsigned int size) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void pci_add_dma_alias(Ptr<pci_dev> dev, char devfn_from, @Unsigned int nr_devfns) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int pci_add_dynid(Ptr<pci_driver> drv, @Unsigned int vendor, @Unsigned int device,
      @Unsigned int subvendor, @Unsigned int subdevice, @Unsigned int _class,
      @Unsigned int class_mask, @Unsigned long driver_data) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int pci_add_ext_cap_save_buffer(Ptr<pci_dev> dev, @Unsigned short cap,
      @Unsigned int size) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static Ptr<pci_bus> pci_add_new_bus(Ptr<pci_bus> parent, Ptr<pci_dev> dev, int busnr) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void pci_add_resource(Ptr<list_head> resources, Ptr<resource> res) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void pci_add_resource_offset(Ptr<list_head> resources, Ptr<resource> res,
      @Unsigned @OriginalName("resource_size_t") long offset) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static @Unsigned long pci_address_to_pio(
      @Unsigned @OriginalName("phys_addr_t") long address) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static boolean pci_aer_available() {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void pci_aer_clear_fatal_status(Ptr<pci_dev> dev) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int pci_aer_clear_nonfatal_status(Ptr<pci_dev> dev) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int pci_aer_clear_status(Ptr<pci_dev> dev) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void pci_aer_exit(Ptr<pci_dev> dev) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void pci_aer_init(Ptr<pci_dev> dev) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int pci_aer_raw_clear_status(Ptr<pci_dev> dev) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int pci_af_flr(Ptr<pci_dev> dev, boolean probe) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static Ptr<pci_bus> pci_alloc_bus(Ptr<pci_bus> parent) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static Ptr<pci_bus> pci_alloc_child_bus(Ptr<pci_bus> parent, Ptr<pci_dev> bridge,
      int busnr) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static Ptr<pci_dev> pci_alloc_dev(Ptr<pci_bus> bus) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static Ptr<pci_host_bridge> pci_alloc_host_bridge(@Unsigned long priv) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int pci_alloc_irq_vectors(Ptr<pci_dev> dev, @Unsigned int min_vecs,
      @Unsigned int max_vecs, @Unsigned int flags) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int pci_alloc_irq_vectors_affinity(Ptr<pci_dev> dev, @Unsigned int min_vecs,
      @Unsigned int max_vecs, @Unsigned int flags, Ptr<irq_affinity> affd) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static Ptr<?> pci_alloc_p2pmem(Ptr<pci_dev> pdev, @Unsigned long size) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void pci_allocate_cap_save_buffers(Ptr<pci_dev> dev) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void pci_allocate_vc_save_buffers(Ptr<pci_dev> dev) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void pci_amd_enable_64bit_bar(Ptr<pci_dev> dev) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int pci_apply_final_quirks() {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int pci_arch_init() {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void pci_assign_irq(Ptr<pci_dev> dev) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int pci_assign_resource(Ptr<pci_dev> dev, int resno) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void pci_assign_unassigned_bridge_resources(Ptr<pci_dev> bridge) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void pci_assign_unassigned_bus_resources(Ptr<pci_bus> bus) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void pci_assign_unassigned_resources() {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void pci_assign_unassigned_root_bus_resources(Ptr<pci_bus> bus) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static boolean pci_ats_disabled() {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void pci_ats_init(Ptr<pci_dev> dev) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int pci_ats_page_aligned(Ptr<pci_dev> pdev) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int pci_ats_queue_depth(Ptr<pci_dev> dev) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static boolean pci_ats_supported(Ptr<pci_dev> dev) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int pci_back_from_sleep(Ptr<pci_dev> dev) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static @Unsigned long pci_biosrom_size(Ptr<pci_dev> pdev) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("pci_brcm_trumanage_setup($arg1, (const struct pciserial_board*)$arg2, $arg3, $arg4)")
  public static int pci_brcm_trumanage_setup(Ptr<serial_private> priv, Ptr<pciserial_board> board,
      Ptr<uart_8250_port> port, int idx) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static @Unsigned @OriginalName("umode_t") short pci_bridge_attrs_are_visible(
      Ptr<kobject> kobj, Ptr<attribute> a, int n) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static boolean pci_bridge_d3_possible(Ptr<pci_dev> bridge) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void pci_bridge_d3_update(Ptr<pci_dev> dev) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void pci_bridge_distribute_available_resources(Ptr<pci_dev> bridge,
      Ptr<list_head> add_list) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void pci_bridge_reconfigure_ltr(Ptr<pci_dev> pdev) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int pci_bridge_secondary_bus_reset(Ptr<pci_dev> dev) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int pci_bridge_wait_for_secondary_bus(Ptr<pci_dev> dev, String reset_type) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void pci_bus_add_device(Ptr<pci_dev> dev) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("pci_bus_add_devices((const struct pci_bus*)$arg1)")
  public static void pci_bus_add_devices(Ptr<pci_bus> bus) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void pci_bus_add_resource(Ptr<pci_bus> bus, Ptr<resource> res) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int pci_bus_alloc_from_region(Ptr<pci_bus> bus, Ptr<resource> res,
      @Unsigned @OriginalName("resource_size_t") long size,
      @Unsigned @OriginalName("resource_size_t") long align,
      @Unsigned @OriginalName("resource_size_t") long min, @Unsigned long type_mask,
      @OriginalName("resource_alignf") Ptr<?> alignf, Ptr<?> alignf_data,
      Ptr<pci_bus_region> region) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int pci_bus_alloc_resource(Ptr<pci_bus> bus, Ptr<resource> res,
      @Unsigned @OriginalName("resource_size_t") long size,
      @Unsigned @OriginalName("resource_size_t") long align,
      @Unsigned @OriginalName("resource_size_t") long min, @Unsigned long type_mask,
      @OriginalName("resource_alignf") Ptr<?> alignf, Ptr<?> alignf_data) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void pci_bus_allocate_dev_resources(Ptr<pci_bus> b) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void pci_bus_allocate_resources(Ptr<pci_bus> b) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("pci_bus_assign_resources((const struct pci_bus*)$arg1)")
  public static void pci_bus_assign_resources(Ptr<pci_bus> bus) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void pci_bus_claim_resources(Ptr<pci_bus> b) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static boolean pci_bus_clip_resource(Ptr<pci_dev> dev, int idx) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void pci_bus_distribute_available_resources(Ptr<pci_bus> bus,
      Ptr<list_head> add_list, resource io, resource mmio, resource mmio_pref) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void pci_bus_dump_resources(Ptr<pci_bus> bus) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int pci_bus_error_reset(Ptr<pci_dev> bridge) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static char pci_bus_find_capability(Ptr<pci_bus> bus, @Unsigned int devfn, int cap) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static boolean pci_bus_generic_read_dev_vendor_id(Ptr<pci_bus> bus, int devfn,
      Ptr<java.lang. @Unsigned Integer> l, int timeout) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static Ptr<pci_bus> pci_bus_get(Ptr<pci_bus> bus) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int pci_bus_get_depth(Ptr<pci_bus> bus) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int pci_bus_insert_busn_res(Ptr<pci_bus> b, int bus, int bus_max) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void pci_bus_lock(Ptr<pci_bus> bus) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("pci_bus_match($arg1, (const struct device_driver*)$arg2)")
  public static int pci_bus_match(Ptr<device> dev, Ptr<device_driver> drv) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static char pci_bus_max_busnr(Ptr<pci_bus> bus) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int pci_bus_num_vf(Ptr<device> dev) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void pci_bus_put(Ptr<pci_bus> bus) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int pci_bus_read_config_byte(Ptr<pci_bus> bus, @Unsigned int devfn, int pos,
      Ptr<java.lang.Character> value) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int pci_bus_read_config_dword(Ptr<pci_bus> bus, @Unsigned int devfn, int pos,
      Ptr<java.lang. @Unsigned Integer> value) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int pci_bus_read_config_word(Ptr<pci_bus> bus, @Unsigned int devfn, int pos,
      Ptr<java.lang. @Unsigned Short> value) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static boolean pci_bus_read_dev_vendor_id(Ptr<pci_bus> bus, int devfn,
      Ptr<java.lang. @Unsigned Integer> l, int timeout) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void pci_bus_release_bridge_resources(Ptr<pci_bus> bus, @Unsigned long type,
      release_type rel_type) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void pci_bus_release_busn_res(Ptr<pci_bus> b) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void pci_bus_remove_resource(Ptr<pci_bus> bus, Ptr<resource> res) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void pci_bus_remove_resources(Ptr<pci_bus> bus) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static boolean pci_bus_resettable(Ptr<pci_bus> bus) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("pci_bus_resource_n((const struct pci_bus*)$arg1, $arg2)")
  public static Ptr<resource> pci_bus_resource_n(Ptr<pci_bus> bus, int n) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void pci_bus_restore_locked(Ptr<pci_bus> bus) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void pci_bus_save_and_disable_locked(Ptr<pci_bus> bus) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void pci_bus_set_current_state(Ptr<pci_bus> bus,
      @OriginalName("pci_power_t") int state) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static Ptr<pci_ops> pci_bus_set_ops(Ptr<pci_bus> bus, Ptr<pci_ops> ops) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void pci_bus_size_bridges(Ptr<pci_bus> bus) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int pci_bus_trylock(Ptr<pci_bus> bus) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void pci_bus_unlock(Ptr<pci_bus> bus) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int pci_bus_update_busn_res_end(Ptr<pci_bus> b, int bus_max) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int pci_bus_write_config_byte(Ptr<pci_bus> bus, @Unsigned int devfn, int pos,
      char value) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int pci_bus_write_config_dword(Ptr<pci_bus> bus, @Unsigned int devfn, int pos,
      @Unsigned int value) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int pci_bus_write_config_word(Ptr<pci_bus> bus, @Unsigned int devfn, int pos,
      @Unsigned short value) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("pci_call_probe($arg1, $arg2, (const struct pci_device_id*)$arg3)")
  public static int pci_call_probe(Ptr<pci_driver> drv, Ptr<pci_dev> dev, Ptr<pci_device_id> id) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static @Unsigned long pci_cardbus_resource_alignment(Ptr<resource> res) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void pci_cfg_access_lock(Ptr<pci_dev> dev) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static boolean pci_cfg_access_trylock(Ptr<pci_dev> dev) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void pci_cfg_access_unlock(Ptr<pci_dev> dev) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int pci_cfg_space_size(Ptr<pci_dev> dev) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int pci_cfg_space_size_ext(Ptr<pci_dev> dev) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static boolean pci_check_and_mask_intx(Ptr<pci_dev> dev) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static boolean pci_check_and_set_intx_mask(Ptr<pci_dev> dev, boolean mask) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static boolean pci_check_and_unmask_intx(Ptr<pci_dev> dev) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static boolean pci_check_pme_status(Ptr<pci_dev> dev) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int pci_check_type1() {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int pci_check_type2() {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static @OriginalName("pci_power_t") int pci_choose_state(Ptr<pci_dev> dev,
      @OriginalName("pm_message_t") pm_message state) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int pci_claim_bridge_resource(Ptr<pci_dev> bridge, int i) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int pci_claim_resource(Ptr<pci_dev> dev, int resource) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("pci_clear_and_set_config_dword((const struct pci_dev*)$arg1, $arg2, $arg3, $arg4)")
  public static void pci_clear_and_set_config_dword(Ptr<pci_dev> dev, int pos, @Unsigned int clear,
      @Unsigned int set) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void pci_clear_master(Ptr<pci_dev> dev) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void pci_clear_mwi(Ptr<pci_dev> dev) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static char pci_common_swizzle(Ptr<pci_dev> dev, Ptr<java.lang.Character> pinp) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int pci_conf1_read(@Unsigned int seg, @Unsigned int bus, @Unsigned int devfn,
      int reg, int len, Ptr<java.lang. @Unsigned Integer> value) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int pci_conf1_write(@Unsigned int seg, @Unsigned int bus, @Unsigned int devfn,
      int reg, int len, @Unsigned int value) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int pci_conf2_read(@Unsigned int seg, @Unsigned int bus, @Unsigned int devfn,
      int reg, int len, Ptr<java.lang. @Unsigned Integer> value) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int pci_conf2_write(@Unsigned int seg, @Unsigned int bus, @Unsigned int devfn,
      int reg, int len, @Unsigned int value) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void pci_config_pm_runtime_get(Ptr<pci_dev> pdev) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void pci_config_pm_runtime_put(Ptr<pci_dev> pdev) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void pci_configure_ari(Ptr<pci_dev> dev) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void pci_configure_aspm_l1ss(Ptr<pci_dev> pdev) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void pci_configure_device(Ptr<pci_dev> dev) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int pci_configure_extended_tags(Ptr<pci_dev> dev, Ptr<?> ign) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void pci_configure_ltr(Ptr<pci_dev> pdev) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void pci_configure_mps(Ptr<pci_dev> dev) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int pci_create_attr(Ptr<pci_dev> pdev, int num, int write_combine) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void pci_create_device_link(Ptr<pci_dev> pdev, @Unsigned int consumer,
      @Unsigned int supplier, @Unsigned int _class, @Unsigned int class_shift) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int pci_create_resource_files(Ptr<pci_dev> pdev) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static Ptr<pci_bus> pci_create_root_bus(Ptr<device> parent, int bus, Ptr<pci_ops> ops,
      Ptr<?> sysdata, Ptr<list_head> resources) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("pci_create_slot($arg1, $arg2, (const u8*)$arg3, $arg4)")
  public static Ptr<pci_slot> pci_create_slot(Ptr<pci_bus> parent, int slot_nr, String name,
      Ptr<hotplug_slot> hotplug) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int pci_create_sysfs_dev_files(Ptr<pci_dev> pdev) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void pci_d3cold_disable(Ptr<pci_dev> dev) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void pci_d3cold_enable(Ptr<pci_dev> dev) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("pci_default_setup($arg1, (const struct pciserial_board*)$arg2, $arg3, $arg4)")
  public static int pci_default_setup(Ptr<serial_private> priv, Ptr<pciserial_board> board,
      Ptr<uart_8250_port> port, int idx) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void pci_destroy_slot(Ptr<pci_slot> slot) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int pci_dev_acpi_reset(Ptr<pci_dev> dev, boolean probe) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void pci_dev_adjust_pme(Ptr<pci_dev> pci_dev) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void pci_dev_assign_slot(Ptr<pci_dev> dev) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static @Unsigned @OriginalName("umode_t") short pci_dev_attrs_are_visible(
      Ptr<kobject> kobj, Ptr<attribute> a, int n) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int pci_dev_check_d3cold(Ptr<pci_dev> dev, Ptr<?> data) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void pci_dev_complete_resume(Ptr<pci_dev> pci_dev) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("pci_dev_config_attr_bin_size($arg1, (const struct bin_attribute*)$arg2, $arg3)")
  public static @Unsigned long pci_dev_config_attr_bin_size(Ptr<kobject> kobj, Ptr<bin_attribute> a,
      int n) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("pci_dev_driver((const struct pci_dev*)$arg1)")
  public static Ptr<pci_driver> pci_dev_driver(Ptr<pci_dev> dev) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static Ptr<pci_dev> pci_dev_get(Ptr<pci_dev> dev) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static boolean pci_dev_has_default_msi_parent_domain(Ptr<pci_dev> dev) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static @Unsigned @OriginalName("umode_t") short pci_dev_hp_attrs_are_visible(
      Ptr<kobject> kobj, Ptr<attribute> a, int n) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void pci_dev_lock(Ptr<pci_dev> dev) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static boolean pci_dev_need_resume(Ptr<pci_dev> pci_dev) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("pci_dev_present((const struct pci_device_id*)$arg1)")
  public static int pci_dev_present(Ptr<pci_device_id> ids) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void pci_dev_put(Ptr<pci_dev> dev) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static @Unsigned @OriginalName("umode_t") short pci_dev_reset_attr_is_visible(
      Ptr<kobject> kobj, Ptr<attribute> a, int n) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void pci_dev_restore(Ptr<pci_dev> dev) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("pci_dev_rom_attr_bin_size($arg1, (const struct bin_attribute*)$arg2, $arg3)")
  public static @Unsigned long pci_dev_rom_attr_bin_size(Ptr<kobject> kobj, Ptr<bin_attribute> a,
      int n) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("pci_dev_rom_attr_is_visible($arg1, (const struct bin_attribute*)$arg2, $arg3)")
  public static @Unsigned @OriginalName("umode_t") short pci_dev_rom_attr_is_visible(
      Ptr<kobject> kobj, Ptr<bin_attribute> a, int n) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static boolean pci_dev_run_wake(Ptr<pci_dev> dev) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void pci_dev_save_and_disable(Ptr<pci_dev> dev) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int pci_dev_set_disconnected(Ptr<pci_dev> dev, Ptr<?> unused) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int pci_dev_specific_acs_enabled(Ptr<pci_dev> dev, @Unsigned short acs_flags) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int pci_dev_specific_disable_acs_redir(Ptr<pci_dev> dev) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int pci_dev_specific_enable_acs(Ptr<pci_dev> dev) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int pci_dev_specific_reset(Ptr<pci_dev> dev, boolean probe) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("pci_dev_str_match($arg1, (const u8*)$arg2, (const u8**)$arg3)")
  public static int pci_dev_str_match(Ptr<pci_dev> dev, String p, Ptr<String> endptr) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("pci_dev_str_match_path($arg1, (const u8*)$arg2, (const u8**)$arg3)")
  public static int pci_dev_str_match_path(Ptr<pci_dev> dev, String path, Ptr<String> endptr) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int pci_dev_trylock(Ptr<pci_dev> dev) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void pci_dev_unlock(Ptr<pci_dev> dev) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int pci_dev_wait(Ptr<pci_dev> dev, String reset_type, int timeout) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void pci_device_add(Ptr<pci_dev> dev, Ptr<pci_bus> bus) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void pci_device_domain_set_desc(
      Ptr<@OriginalName("msi_alloc_info_t") irq_alloc_info> arg, Ptr<msi_desc> desc) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static Ptr<iommu_group> pci_device_group(Ptr<device> dev) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("((const struct cpumask*)pci_device_irq_get_affinity($arg1, $arg2))")
  public static Ptr<cpumask> pci_device_irq_get_affinity(Ptr<device> dev, @Unsigned int irq_vec) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static boolean pci_device_is_present(Ptr<pci_dev> pdev) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int pci_device_probe(Ptr<device> dev) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void pci_device_remove(Ptr<device> dev) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void pci_device_shutdown(Ptr<device> dev) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static boolean pci_devs_are_dma_aliases(Ptr<pci_dev> dev1, Ptr<pci_dev> dev2) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void pci_direct_init(int type) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int pci_direct_probe() {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void pci_disable_ats(Ptr<pci_dev> dev) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void pci_disable_bridge_window(Ptr<pci_dev> dev) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void pci_disable_device(Ptr<pci_dev> dev) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void pci_disable_enabled_device(Ptr<pci_dev> dev) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int pci_disable_link_state(Ptr<pci_dev> pdev, int state) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int pci_disable_link_state_locked(Ptr<pci_dev> pdev, int state) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void pci_disable_msi(Ptr<pci_dev> dev) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void pci_disable_msix(Ptr<pci_dev> dev) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void pci_disable_parity(Ptr<pci_dev> dev) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void pci_disable_pasid(Ptr<pci_dev> pdev) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void pci_disable_pri(Ptr<pci_dev> pdev) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void pci_disable_ptm(Ptr<pci_dev> dev) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void pci_disable_rom(Ptr<pci_dev> pdev) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void pci_disable_sriov(Ptr<pci_dev> dev) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void pci_dma_cleanup(Ptr<device> dev) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int pci_dma_configure(Ptr<device> dev) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static Ptr<pci_bus> pci_do_find_bus(Ptr<pci_bus> bus, char busnr) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("pci_doe($arg1, $arg2, $arg3, (const void*)$arg4, $arg5, $arg6, $arg7)")
  public static int pci_doe(Ptr<pci_doe_mb> doe_mb, @Unsigned short vendor, char type,
      Ptr<?> request, @Unsigned long request_sz, Ptr<?> response, @Unsigned long response_sz) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int pci_doe_abort(Ptr<pci_doe_mb> doe_mb) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int pci_doe_cache_features(Ptr<pci_doe_mb> doe_mb) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void pci_doe_cancel_tasks(Ptr<pci_doe_mb> doe_mb) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static Ptr<pci_doe_mb> pci_doe_create_mb(Ptr<pci_dev> pdev, @Unsigned short cap_offset) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void pci_doe_destroy(Ptr<pci_dev> pdev) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void pci_doe_disconnected(Ptr<pci_dev> pdev) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void pci_doe_init(Ptr<pci_dev> pdev) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int pci_doe_recv_resp(Ptr<pci_doe_mb> doe_mb, Ptr<pci_doe_task> task) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int pci_doe_send_req(Ptr<pci_doe_mb> doe_mb, Ptr<pci_doe_task> task) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static boolean pci_doe_supports_feat(Ptr<pci_doe_mb> doe_mb, @Unsigned short vid,
      char type) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int pci_doe_sysfs_feature_populate(Ptr<pci_dev> pdev, Ptr<pci_doe_mb> doe_mb) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void pci_doe_sysfs_feature_remove(Ptr<pci_dev> pdev, Ptr<pci_doe_mb> doe_mb) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static @OriginalName("ssize_t") long pci_doe_sysfs_feature_show(Ptr<device> dev,
      Ptr<device_attribute> attr, String buf) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void pci_doe_sysfs_init(Ptr<pci_dev> pdev) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void pci_doe_sysfs_teardown(Ptr<pci_dev> pdev) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void pci_doe_task_complete(Ptr<pci_doe_task> task) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int pci_doe_wait(Ptr<pci_doe_mb> doe_mb, @Unsigned long timeout) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void pci_dpc_init(Ptr<pci_dev> pdev) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static boolean pci_dpc_recovered(Ptr<pci_dev> pdev) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int pci_driver_init() {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void pci_ea_init(Ptr<pci_dev> dev) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int pci_ea_read(Ptr<pci_dev> dev, int offset) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static @Unsigned int pci_early_find_cap(int bus, int slot, int func, int cap) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void pci_early_fixup_cyrix_5530(Ptr<pci_dev> dev) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int pci_eg20t_init(Ptr<pci_dev> dev) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void pci_enable_acs(Ptr<pci_dev> dev) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int pci_enable_atomic_ops_to_root(Ptr<pci_dev> dev, @Unsigned int cap_mask) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int pci_enable_ats(Ptr<pci_dev> dev, int ps) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void pci_enable_bridge(Ptr<pci_dev> dev) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int pci_enable_device(Ptr<pci_dev> dev) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int pci_enable_device_flags(Ptr<pci_dev> dev, @Unsigned long flags) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int pci_enable_device_mem(Ptr<pci_dev> dev) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int pci_enable_link_state(Ptr<pci_dev> pdev, int state) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int pci_enable_link_state_locked(Ptr<pci_dev> pdev, int state) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int pci_enable_msi(Ptr<pci_dev> dev) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int pci_enable_msix_range(Ptr<pci_dev> dev, Ptr<msix_entry> entries, int minvec,
      int maxvec) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int pci_enable_pasid(Ptr<pci_dev> pdev, int features) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int pci_enable_pri(Ptr<pci_dev> pdev, @Unsigned int reqs) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int pci_enable_ptm(Ptr<pci_dev> dev, Ptr<java.lang.Character> granularity) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int pci_enable_resources(Ptr<pci_dev> dev, int mask) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int pci_enable_rom(Ptr<pci_dev> pdev) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int pci_enable_sriov(Ptr<pci_dev> dev, int nr_virtfn) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int pci_enable_wake(Ptr<pci_dev> pci_dev, @OriginalName("pci_power_t") int state,
      boolean enable) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("pci_ep_cfs_add_epc_group((const u8*)$arg1)")
  public static Ptr<config_group> pci_ep_cfs_add_epc_group(String name) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("pci_ep_cfs_add_epf_group((const u8*)$arg1)")
  public static Ptr<config_group> pci_ep_cfs_add_epf_group(String name) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void pci_ep_cfs_exit() {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int pci_ep_cfs_init() {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void pci_ep_cfs_remove_epc_group(Ptr<config_group> group) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void pci_ep_cfs_remove_epf_group(Ptr<config_group> group) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int pci_epc_add_epf(Ptr<pci_epc> epc, Ptr<pci_epf> epf,
      pci_epc_interface_type type) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int pci_epc_bar_size_to_rebar_cap(@Unsigned long size,
      Ptr<java.lang. @Unsigned Integer> cap) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void pci_epc_bus_master_enable_notify(Ptr<pci_epc> epc) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void pci_epc_clear_bar(Ptr<pci_epc> epc, char func_no, char vfunc_no,
      Ptr<pci_epf_bar> epf_bar) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void pci_epc_deinit_notify(Ptr<pci_epc> epc) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void pci_epc_destroy(Ptr<pci_epc> epc) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int pci_epc_epf_link(Ptr<config_item> epc_item, Ptr<config_item> epf_item) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void pci_epc_epf_unlink(Ptr<config_item> epc_item, Ptr<config_item> epf_item) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void pci_epc_exit() {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("pci_epc_get((const u8*)$arg1)")
  public static Ptr<pci_epc> pci_epc_get(String epc_name) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("((const struct pci_epc_features*)pci_epc_get_features($arg1, $arg2, $arg3))")
  public static Ptr<pci_epc_features> pci_epc_get_features(Ptr<pci_epc> epc, char func_no,
      char vfunc_no) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("pci_epc_get_first_free_bar((const struct pci_epc_features*)$arg1)")
  public static pci_barno pci_epc_get_first_free_bar(Ptr<pci_epc_features> epc_features) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int pci_epc_get_msi(Ptr<pci_epc> epc, char func_no, char vfunc_no) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int pci_epc_get_msix(Ptr<pci_epc> epc, char func_no, char vfunc_no) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("pci_epc_get_next_free_bar((const struct pci_epc_features*)$arg1, $arg2)")
  public static pci_barno pci_epc_get_next_free_bar(Ptr<pci_epc_features> epc_features,
      pci_barno bar) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int pci_epc_init() {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void pci_epc_init_notify(Ptr<pci_epc> epc) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void pci_epc_linkdown(Ptr<pci_epc> epc) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void pci_epc_linkup(Ptr<pci_epc> epc) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int pci_epc_map_addr(Ptr<pci_epc> epc, char func_no, char vfunc_no,
      @Unsigned @OriginalName("phys_addr_t") long phys_addr, @Unsigned long pci_addr,
      @Unsigned long size) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int pci_epc_map_msi_irq(Ptr<pci_epc> epc, char func_no, char vfunc_no,
      @Unsigned @OriginalName("phys_addr_t") long phys_addr, char interrupt_num,
      @Unsigned int entry_size, Ptr<java.lang. @Unsigned Integer> msi_data,
      Ptr<java.lang. @Unsigned Integer> msi_addr_offset) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static Ptr<?> pci_epc_mem_alloc_addr(Ptr<pci_epc> epc,
      Ptr<java.lang. @Unsigned @OriginalName("phys_addr_t") Long> phys_addr, @Unsigned long size) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void pci_epc_mem_exit(Ptr<pci_epc> epc) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void pci_epc_mem_free_addr(Ptr<pci_epc> epc,
      @Unsigned @OriginalName("phys_addr_t") long phys_addr, Ptr<?> virt_addr,
      @Unsigned long size) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int pci_epc_mem_init(Ptr<pci_epc> epc,
      @Unsigned @OriginalName("phys_addr_t") long base, @Unsigned long size,
      @Unsigned long page_size) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int pci_epc_mem_map(Ptr<pci_epc> epc, char func_no, char vfunc_no,
      @Unsigned long pci_addr, @Unsigned long pci_size, Ptr<pci_epc_map> map) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void pci_epc_mem_unmap(Ptr<pci_epc> epc, char func_no, char vfunc_no,
      Ptr<pci_epc_map> map) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int pci_epc_multi_mem_init(Ptr<pci_epc> epc, Ptr<pci_epc_mem_window> windows,
      @Unsigned int num_windows) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void pci_epc_notify_pending_init(Ptr<pci_epc> epc, Ptr<pci_epf> epf) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void pci_epc_put(Ptr<pci_epc> epc) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int pci_epc_raise_irq(Ptr<pci_epc> epc, char func_no, char vfunc_no,
      @Unsigned int type, @Unsigned short interrupt_num) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void pci_epc_release(Ptr<device> dev) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void pci_epc_remove_epf(Ptr<pci_epc> epc, Ptr<pci_epf> epf,
      pci_epc_interface_type type) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int pci_epc_set_bar(Ptr<pci_epc> epc, char func_no, char vfunc_no,
      Ptr<pci_epf_bar> epf_bar) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int pci_epc_set_msi(Ptr<pci_epc> epc, char func_no, char vfunc_no, char nr_irqs) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int pci_epc_set_msix(Ptr<pci_epc> epc, char func_no, char vfunc_no,
      @Unsigned short nr_irqs, pci_barno bir, @Unsigned int offset) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int pci_epc_start(Ptr<pci_epc> epc) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static @OriginalName("ssize_t") long pci_epc_start_show(Ptr<config_item> item,
      String page) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("pci_epc_start_store($arg1, (const u8*)$arg2, $arg3)")
  public static @OriginalName("ssize_t") long pci_epc_start_store(Ptr<config_item> item,
      String page, @Unsigned long len) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void pci_epc_stop(Ptr<pci_epc> epc) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void pci_epc_unmap_addr(Ptr<pci_epc> epc, char func_no, char vfunc_no,
      @Unsigned @OriginalName("phys_addr_t") long phys_addr) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int pci_epc_write_header(Ptr<pci_epc> epc, char func_no, char vfunc_no,
      Ptr<pci_epf_header> header) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int pci_epf_add_vepf(Ptr<pci_epf> epf_pf, Ptr<pci_epf> epf_vf) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int pci_epf_align_inbound_addr(Ptr<pci_epf> epf, pci_barno bar, @Unsigned long addr,
      Ptr<java.lang. @Unsigned @OriginalName("dma_addr_t") Long> base,
      Ptr<java.lang. @Unsigned Long> off) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int pci_epf_alloc_doorbell(Ptr<pci_epf> epf, @Unsigned short num_db) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("pci_epf_alloc_space($arg1, $arg2, $arg3, (const struct pci_epc_features*)$arg4, $arg5)")
  public static Ptr<?> pci_epf_alloc_space(Ptr<pci_epf> epf, @Unsigned long size, pci_barno bar,
      Ptr<pci_epc_features> epc_features, pci_epc_interface_type type) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static @OriginalName("ssize_t") long pci_epf_baseclass_code_show(Ptr<config_item> item,
      String page) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("pci_epf_baseclass_code_store($arg1, (const u8*)$arg2, $arg3)")
  public static @OriginalName("ssize_t") long pci_epf_baseclass_code_store(Ptr<config_item> item,
      String page, @Unsigned long len) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int pci_epf_bind(Ptr<pci_epf> epf) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static @OriginalName("ssize_t") long pci_epf_cache_line_size_show(Ptr<config_item> item,
      String page) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("pci_epf_cache_line_size_store($arg1, (const u8*)$arg2, $arg3)")
  public static @OriginalName("ssize_t") long pci_epf_cache_line_size_store(Ptr<config_item> item,
      String page, @Unsigned long len) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void pci_epf_cfs_work(Ptr<work_struct> work) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("pci_epf_create((const u8*)$arg1)")
  public static Ptr<pci_epf> pci_epf_create(String name) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void pci_epf_destroy(Ptr<pci_epf> epf) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void pci_epf_dev_release(Ptr<device> dev) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("pci_epf_device_match($arg1, (const struct device_driver*)$arg2)")
  public static int pci_epf_device_match(Ptr<device> dev, Ptr<device_driver> drv) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int pci_epf_device_probe(Ptr<device> dev) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void pci_epf_device_remove(Ptr<device> dev) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static @OriginalName("ssize_t") long pci_epf_deviceid_show(Ptr<config_item> item,
      String page) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("pci_epf_deviceid_store($arg1, (const u8*)$arg2, $arg3)")
  public static @OriginalName("ssize_t") long pci_epf_deviceid_store(Ptr<config_item> item,
      String page, @Unsigned long len) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void pci_epf_drop(Ptr<config_group> group, Ptr<config_item> item) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void pci_epf_exit() {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void pci_epf_free_doorbell(Ptr<pci_epf> epf) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void pci_epf_free_space(Ptr<pci_epf> epf, Ptr<?> addr, pci_barno bar,
      pci_epc_interface_type type) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int pci_epf_init() {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static @OriginalName("ssize_t") long pci_epf_interrupt_pin_show(Ptr<config_item> item,
      String page) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("pci_epf_interrupt_pin_store($arg1, (const u8*)$arg2, $arg3)")
  public static @OriginalName("ssize_t") long pci_epf_interrupt_pin_store(Ptr<config_item> item,
      String page, @Unsigned long len) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("pci_epf_make($arg1, (const u8*)$arg2)")
  public static Ptr<config_group> pci_epf_make(Ptr<config_group> group, String name) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static @OriginalName("ssize_t") long pci_epf_msi_interrupts_show(Ptr<config_item> item,
      String page) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("pci_epf_msi_interrupts_store($arg1, (const u8*)$arg2, $arg3)")
  public static @OriginalName("ssize_t") long pci_epf_msi_interrupts_store(Ptr<config_item> item,
      String page, @Unsigned long len) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static @OriginalName("ssize_t") long pci_epf_msix_interrupts_show(Ptr<config_item> item,
      String page) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("pci_epf_msix_interrupts_store($arg1, (const u8*)$arg2, $arg3)")
  public static @OriginalName("ssize_t") long pci_epf_msix_interrupts_store(Ptr<config_item> item,
      String page, @Unsigned long len) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static @OriginalName("ssize_t") long pci_epf_progif_code_show(Ptr<config_item> item,
      String page) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("pci_epf_progif_code_store($arg1, (const u8*)$arg2, $arg3)")
  public static @OriginalName("ssize_t") long pci_epf_progif_code_store(Ptr<config_item> item,
      String page, @Unsigned long len) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void pci_epf_release(Ptr<config_item> item) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void pci_epf_remove_cfs(Ptr<pci_epf_driver> driver) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void pci_epf_remove_vepf(Ptr<pci_epf> epf_pf, Ptr<pci_epf> epf_vf) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static @OriginalName("ssize_t") long pci_epf_revid_show(Ptr<config_item> item,
      String page) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("pci_epf_revid_store($arg1, (const u8*)$arg2, $arg3)")
  public static @OriginalName("ssize_t") long pci_epf_revid_store(Ptr<config_item> item,
      String page, @Unsigned long len) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static @OriginalName("ssize_t") long pci_epf_subclass_code_show(Ptr<config_item> item,
      String page) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("pci_epf_subclass_code_store($arg1, (const u8*)$arg2, $arg3)")
  public static @OriginalName("ssize_t") long pci_epf_subclass_code_store(Ptr<config_item> item,
      String page, @Unsigned long len) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static @OriginalName("ssize_t") long pci_epf_subsys_id_show(Ptr<config_item> item,
      String page) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("pci_epf_subsys_id_store($arg1, (const u8*)$arg2, $arg3)")
  public static @OriginalName("ssize_t") long pci_epf_subsys_id_store(Ptr<config_item> item,
      String page, @Unsigned long len) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static @OriginalName("ssize_t") long pci_epf_subsys_vendor_id_show(Ptr<config_item> item,
      String page) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("pci_epf_subsys_vendor_id_store($arg1, (const u8*)$arg2, $arg3)")
  public static @OriginalName("ssize_t") long pci_epf_subsys_vendor_id_store(Ptr<config_item> item,
      String page, @Unsigned long len) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void pci_epf_unbind(Ptr<pci_epf> epf) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void pci_epf_unregister_driver(Ptr<pci_epf_driver> driver) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static @OriginalName("ssize_t") long pci_epf_vendorid_show(Ptr<config_item> item,
      String page) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("pci_epf_vendorid_store($arg1, (const u8*)$arg2, $arg3)")
  public static @OriginalName("ssize_t") long pci_epf_vendorid_store(Ptr<config_item> item,
      String page, @Unsigned long len) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int pci_epf_vepf_link(Ptr<config_item> epf_pf_item, Ptr<config_item> epf_vf_item) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void pci_epf_vepf_unlink(Ptr<config_item> epf_pf_item,
      Ptr<config_item> epf_vf_item) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int pci_ext_cfg_avail() {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static Ptr<pci_bus> pci_find_bus(int domain, int busnr) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static char pci_find_capability(Ptr<pci_dev> dev, int cap) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static Ptr<pci_doe_mb> pci_find_doe_mailbox(Ptr<pci_dev> pdev, @Unsigned short vendor,
      char type) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static @Unsigned short pci_find_dvsec_capability(Ptr<pci_dev> dev, @Unsigned short vendor,
      @Unsigned short dvsec) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static @Unsigned short pci_find_ext_capability(Ptr<pci_dev> dev, int cap) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static Ptr<pci_host_bridge> pci_find_host_bridge(Ptr<pci_bus> bus) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static char pci_find_ht_capability(Ptr<pci_dev> dev, int ht_cap) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("pci_find_next_bus((const struct pci_bus*)$arg1)")
  public static Ptr<pci_bus> pci_find_next_bus(Ptr<pci_bus> from) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static char pci_find_next_capability(Ptr<pci_dev> dev, char pos, int cap) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static @Unsigned short pci_find_next_ext_capability(Ptr<pci_dev> dev,
      @Unsigned short start, int cap) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static char pci_find_next_ht_capability(Ptr<pci_dev> dev, char pos, int ht_cap) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("pci_find_parent_resource((const struct pci_dev*)$arg1, $arg2)")
  public static Ptr<resource> pci_find_parent_resource(Ptr<pci_dev> dev, Ptr<resource> res) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static Ptr<resource> pci_find_resource(Ptr<pci_dev> dev, Ptr<resource> res) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static Ptr<pci_cap_saved_state> pci_find_saved_cap(Ptr<pci_dev> dev, char cap) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static Ptr<pci_cap_saved_state> pci_find_saved_ext_cap(Ptr<pci_dev> dev,
      @Unsigned short cap) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static @Unsigned short pci_find_vsec_capability(Ptr<pci_dev> dev, @Unsigned short vendor,
      int cap) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int pci_finish_runtime_suspend(Ptr<pci_dev> dev) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int pci_fintek_f815xxa_init(Ptr<pci_dev> dev) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("pci_fintek_f815xxa_setup($arg1, (const struct pciserial_board*)$arg2, $arg3, $arg4)")
  public static int pci_fintek_f815xxa_setup(Ptr<serial_private> priv, Ptr<pciserial_board> board,
      Ptr<uart_8250_port> port, int idx) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int pci_fintek_init(Ptr<pci_dev> dev) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int pci_fintek_rs485_config(Ptr<uart_port> port, Ptr<ktermios> termios,
      Ptr<serial_rs485> rs485) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("pci_fintek_setup($arg1, (const struct pciserial_board*)$arg2, $arg3, $arg4)")
  public static int pci_fintek_setup(Ptr<serial_private> priv, Ptr<pciserial_board> board,
      Ptr<uart_8250_port> port, int idx) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void pci_fixup_amd_ehci_pme(Ptr<pci_dev> dev) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void pci_fixup_amd_fch_xhci_pme(Ptr<pci_dev> dev) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void pci_fixup_d3cold_delay_1sec(Ptr<pci_dev> pdev) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void pci_fixup_device(pci_fixup_pass pass, Ptr<pci_dev> dev) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void pci_fixup_i450gx(Ptr<pci_dev> d) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void pci_fixup_i450nx(Ptr<pci_dev> d) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void pci_fixup_latency(Ptr<pci_dev> d) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void pci_fixup_msi_k8t_onboard_sound(Ptr<pci_dev> dev) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void pci_fixup_nforce2(Ptr<pci_dev> dev) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void pci_fixup_no_d0_pme(Ptr<pci_dev> dev) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void pci_fixup_no_msi_no_pme(Ptr<pci_dev> dev) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void pci_fixup_pericom_acs_store_forward(Ptr<pci_dev> pdev) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void pci_fixup_piix4_acpi(Ptr<pci_dev> d) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void pci_fixup_transparent_bridge(Ptr<pci_dev> dev) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void pci_fixup_umc_ide(Ptr<pci_dev> d) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void pci_fixup_via_northbridge_bug(Ptr<pci_dev> d) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void pci_fixup_video(Ptr<pci_dev> pdev) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("pci_for_each_dma_alias($arg1, (int (*)(struct pci_dev*, short unsigned int, void*))$arg2, $arg3)")
  public static int pci_for_each_dma_alias(Ptr<pci_dev> pdev, Ptr<?> fn, Ptr<?> data) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void pci_free_cap_save_buffers(Ptr<pci_dev> dev) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void pci_free_host_bridge(Ptr<pci_host_bridge> bridge) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void pci_free_irq(Ptr<pci_dev> dev, @Unsigned int nr, Ptr<?> dev_id) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void pci_free_irq_vectors(Ptr<pci_dev> dev) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void pci_free_msi_irqs(Ptr<pci_dev> dev) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void pci_free_p2pmem(Ptr<pci_dev> pdev, Ptr<?> addr, @Unsigned long size) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void pci_free_resource_list(Ptr<list_head> resources) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int pci_generic_config_read(Ptr<pci_bus> bus, @Unsigned int devfn, int where,
      int size, Ptr<java.lang. @Unsigned Integer> val) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int pci_generic_config_read32(Ptr<pci_bus> bus, @Unsigned int devfn, int where,
      int size, Ptr<java.lang. @Unsigned Integer> val) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int pci_generic_config_write(Ptr<pci_bus> bus, @Unsigned int devfn, int where,
      int size, @Unsigned int val) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int pci_generic_config_write32(Ptr<pci_bus> bus, @Unsigned int devfn, int where,
      int size, @Unsigned int val) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static Ptr<pci_dev> pci_get_base_class(@Unsigned int _class, Ptr<pci_dev> from) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static Ptr<pci_dev> pci_get_class(@Unsigned int _class, Ptr<pci_dev> from) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static Ptr<pci_dev> pci_get_device(@Unsigned int vendor, @Unsigned int device,
      Ptr<pci_dev> from) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static Ptr<pci_dev> pci_get_domain_bus_and_slot(int domain, @Unsigned int bus,
      @Unsigned int devfn) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static @Unsigned long pci_get_dsn(Ptr<pci_dev> dev) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static Ptr<device> pci_get_host_bridge_device(Ptr<pci_dev> dev) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int pci_get_interrupt_pin(Ptr<pci_dev> dev, Ptr<Ptr<pci_dev>> bridge) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static Ptr<pci_dev> pci_get_slot(Ptr<pci_bus> bus, @Unsigned int devfn) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static Ptr<pci_dev> pci_get_subsys(@Unsigned int vendor, @Unsigned int device,
      @Unsigned int ss_vendor, @Unsigned int ss_device, Ptr<pci_dev> from) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static boolean pci_has_legacy_pm_support(Ptr<pci_dev> pci_dev) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static boolean pci_has_p2pmem(Ptr<pci_dev> pdev) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static Ptr<irq_domain> pci_host_bridge_acpi_msi_domain(Ptr<pci_bus> bus) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int pci_host_probe(Ptr<pci_host_bridge> bridge) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int pci_hotplug_init() {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int pci_hp_add(Ptr<hotplug_slot> slot) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int pci_hp_add_bridge(Ptr<pci_dev> dev) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void pci_hp_del(Ptr<hotplug_slot> slot) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void pci_hp_deregister(Ptr<hotplug_slot> slot) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void pci_hp_destroy(Ptr<hotplug_slot> slot) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int pci_hp_diva_init(Ptr<pci_dev> dev) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("pci_hp_diva_setup($arg1, (const struct pciserial_board*)$arg2, $arg3, $arg4)")
  public static int pci_hp_diva_setup(Ptr<serial_private> priv, Ptr<pciserial_board> board,
      Ptr<uart_8250_port> port, int idx) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void pci_hp_ignore_link_change(Ptr<pci_dev> pdev) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static boolean pci_hp_spurious_link_change(Ptr<pci_dev> pdev) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void pci_hp_unignore_link_change(Ptr<pci_dev> pdev) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int pci_idt_bus_quirk(Ptr<pci_bus> bus, int devfn,
      Ptr<java.lang. @Unsigned Integer> l, int timeout) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void pci_ignore_hotplug(Ptr<pci_dev> dev) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void pci_init_reset_methods(Ptr<pci_dev> dev) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int pci_inteli960ni_init(Ptr<pci_dev> dev) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void pci_intx(Ptr<pci_dev> pdev, int enable) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void pci_invalid_bar(Ptr<pci_dev> dev) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void pci_ioapic_remove(Ptr<acpi_pci_root> root) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static Ptr<?> pci_iomap(Ptr<pci_dev> dev, int bar, @Unsigned long maxlen) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static Ptr<?> pci_iomap_range(Ptr<pci_dev> dev, int bar, @Unsigned long offset,
      @Unsigned long maxlen) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static Ptr<?> pci_iomap_wc(Ptr<pci_dev> dev, int bar, @Unsigned long maxlen) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static Ptr<?> pci_iomap_wc_range(Ptr<pci_dev> dev, int bar, @Unsigned long offset,
      @Unsigned long maxlen) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void pci_iommu_alloc() {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int pci_iommu_init() {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static Ptr<?> pci_ioremap_bar(Ptr<pci_dev> pdev, int bar) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static Ptr<?> pci_ioremap_wc_bar(Ptr<pci_dev> pdev, int bar) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void pci_iounmap(Ptr<pci_dev> dev, Ptr<?> addr) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int pci_iov_add_virtfn(Ptr<pci_dev> dev, int id) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int pci_iov_bus_range(Ptr<pci_bus> bus) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static Ptr<?> pci_iov_get_pf_drvdata(Ptr<pci_dev> dev, Ptr<pci_driver> pf_driver) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int pci_iov_init(Ptr<pci_dev> dev) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static boolean pci_iov_is_memory_decoding_enabled(Ptr<pci_dev> dev) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void pci_iov_release(Ptr<pci_dev> dev) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void pci_iov_remove(Ptr<pci_dev> dev) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void pci_iov_remove_virtfn(Ptr<pci_dev> dev, int id) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void pci_iov_resource_set_size(Ptr<pci_dev> dev, int resno,
      @Unsigned @OriginalName("resource_size_t") long size) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static @Unsigned @OriginalName("resource_size_t") long pci_iov_resource_size(
      Ptr<pci_dev> dev, int resno) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int pci_iov_sysfs_link(Ptr<pci_dev> dev, Ptr<pci_dev> virtfn, int id) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void pci_iov_update_resource(Ptr<pci_dev> dev, int resno) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static @Unsigned int pci_iov_vf_bar_get_sizes(Ptr<pci_dev> dev, int resno, int num_vfs) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int pci_iov_vf_bar_set_size(Ptr<pci_dev> dev, int resno, int size) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int pci_iov_vf_id(Ptr<pci_dev> dev) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int pci_iov_virtfn_bus(Ptr<pci_dev> dev, int vf_id) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int pci_iov_virtfn_devfn(Ptr<pci_dev> dev, int vf_id) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("((const struct cpumask*)pci_irq_get_affinity($arg1, $arg2))")
  public static Ptr<cpumask> pci_irq_get_affinity(Ptr<pci_dev> dev, int nr) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void pci_irq_mask_msi(Ptr<irq_data> data) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void pci_irq_mask_msix(Ptr<irq_data> data) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void pci_irq_shutdown_msi(Ptr<irq_data> data) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void pci_irq_shutdown_msix(Ptr<irq_data> data) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static @Unsigned int pci_irq_startup_msi(Ptr<irq_data> data) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static @Unsigned int pci_irq_startup_msix(Ptr<irq_data> data) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void pci_irq_unmask_msi(Ptr<irq_data> data) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void pci_irq_unmask_msix(Ptr<irq_data> data) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int pci_irq_vector(Ptr<pci_dev> dev, @Unsigned int nr) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void pci_ite887x_exit(Ptr<pci_dev> dev) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int pci_ite887x_init(Ptr<pci_dev> dev) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int pci_legacy_init() {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int pci_legacy_resume(Ptr<device> dev) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int pci_legacy_suspend(Ptr<device> dev,
      @OriginalName("pm_message_t") pm_message state) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("pci_llseek_resource($arg1, $arg2, (const struct bin_attribute*)$arg3, $arg4, $arg5)")
  public static @OriginalName("loff_t") long pci_llseek_resource(Ptr<file> filep, Ptr<kobject> kobj,
      Ptr<bin_attribute> attr, @OriginalName("loff_t") long offset, int whence) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int pci_load_and_free_saved_state(Ptr<pci_dev> dev,
      Ptr<Ptr<pci_saved_state>> state) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int pci_load_saved_state(Ptr<pci_dev> dev, Ptr<pci_saved_state> state) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void pci_lock_rescan_remove() {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static Ptr<?> pci_map_biosrom(Ptr<pci_dev> pdev) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static Ptr<?> pci_map_rom(Ptr<pci_dev> pdev, Ptr<java.lang. @Unsigned Long> size) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void pci_mask_replay_timer_timeout(Ptr<pci_dev> pdev) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("((const struct pci_device_id*)pci_match_device($arg1, $arg2))")
  public static Ptr<pci_device_id> pci_match_device(Ptr<pci_driver> drv, Ptr<pci_dev> dev) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("((const struct pci_device_id*)pci_match_id((const struct pci_device_id*)$arg1, $arg2))")
  public static Ptr<pci_device_id> pci_match_id(Ptr<pci_device_id> ids, Ptr<pci_dev> dev) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int pci_max_pasids(Ptr<pci_dev> pdev) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int pci_mmap_fits(Ptr<pci_dev> pdev, int resno, Ptr<vm_area_struct> vma,
      pci_mmap_api mmap_api) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int pci_mmap_resource_range(Ptr<pci_dev> pdev, int bar, Ptr<vm_area_struct> vma,
      pci_mmap_state mmap_state, int write_combine) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("pci_mmap_resource_uc($arg1, $arg2, (const struct bin_attribute*)$arg3, $arg4)")
  public static int pci_mmap_resource_uc(Ptr<file> filp, Ptr<kobject> kobj, Ptr<bin_attribute> attr,
      Ptr<vm_area_struct> vma) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("pci_mmap_resource_wc($arg1, $arg2, (const struct bin_attribute*)$arg3, $arg4)")
  public static int pci_mmap_resource_wc(Ptr<file> filp, Ptr<kobject> kobj, Ptr<bin_attribute> attr,
      Ptr<vm_area_struct> vma) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("((const u8*)pci_mmcfg_amd_fam10h())")
  public static String pci_mmcfg_amd_fam10h() {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void pci_mmcfg_arch_free() {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int pci_mmcfg_arch_init() {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int pci_mmcfg_arch_map(Ptr<pci_mmcfg_region> cfg) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void pci_mmcfg_arch_unmap(Ptr<pci_mmcfg_region> cfg) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("((const u8*)pci_mmcfg_e7520())")
  public static String pci_mmcfg_e7520() {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void pci_mmcfg_early_init() {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("pci_mmcfg_for_each_region((int (*)(long long unsigned int, long long unsigned int, void*))$arg1, $arg2)")
  public static int pci_mmcfg_for_each_region(Ptr<?> func, Ptr<?> data) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("((const u8*)pci_mmcfg_intel_945())")
  public static String pci_mmcfg_intel_945() {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void pci_mmcfg_late_init() {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int pci_mmcfg_late_insert_resources() {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("((const u8*)pci_mmcfg_nvidia_mcp55())")
  public static String pci_mmcfg_nvidia_mcp55() {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int pci_mmcfg_read(@Unsigned int seg, @Unsigned int bus, @Unsigned int devfn,
      int reg, int len, Ptr<java.lang. @Unsigned Integer> value) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int pci_mmcfg_read_numachip(@Unsigned int seg, @Unsigned int bus,
      @Unsigned int devfn, int reg, int len, Ptr<java.lang. @Unsigned Integer> value) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static boolean pci_mmcfg_reserved(Ptr<device> dev, Ptr<pci_mmcfg_region> cfg, int early) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int pci_mmcfg_write(@Unsigned int seg, @Unsigned int bus, @Unsigned int devfn,
      int reg, int len, @Unsigned int value) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int pci_mmcfg_write_numachip(@Unsigned int seg, @Unsigned int bus,
      @Unsigned int devfn, int reg, int len, @Unsigned int value) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static Ptr<pci_mmcfg_region> pci_mmconfig_add(int segment, int start, int end,
      @Unsigned long addr) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static Ptr<pci_mmcfg_region> pci_mmconfig_alloc(int segment, int start, int end,
      @Unsigned long addr) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int pci_mmconfig_delete(@Unsigned short seg, char start, char end) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int pci_mmconfig_insert(Ptr<device> dev, @Unsigned short seg, char start, char end,
      @Unsigned @OriginalName("phys_addr_t") long addr) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static Ptr<pci_mmcfg_region> pci_mmconfig_lookup(int segment, int bus) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int pci_moxa_init(Ptr<pci_dev> dev) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("pci_moxa_setup($arg1, (const struct pciserial_board*)$arg2, $arg3, $arg4)")
  public static int pci_moxa_setup(Ptr<serial_private> priv, Ptr<pciserial_board> board,
      Ptr<uart_8250_port> port, int idx) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static Ptr<irq_domain> pci_msi_create_irq_domain(Ptr<fwnode_handle> fwnode,
      Ptr<msi_domain_info> info, Ptr<irq_domain> parent) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static @Unsigned int pci_msi_domain_get_msi_rid(Ptr<irq_domain> domain,
      Ptr<pci_dev> pdev) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void pci_msi_domain_set_desc(
      Ptr<@OriginalName("msi_alloc_info_t") irq_alloc_info> arg, Ptr<msi_desc> desc) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static boolean pci_msi_domain_supports(Ptr<pci_dev> pdev, @Unsigned int feature_mask,
      support_mode mode) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void pci_msi_domain_write_msg(Ptr<irq_data> irq_data, Ptr<msi_msg> msg) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static boolean pci_msi_enabled() {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static Ptr<irq_domain> pci_msi_get_device_domain(Ptr<pci_dev> pdev) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void pci_msi_init(Ptr<pci_dev> dev) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static @Unsigned int pci_msi_map_rid_ctlr_node(Ptr<pci_dev> pdev,
      Ptr<Ptr<device_node>> node) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void pci_msi_mask_irq(Ptr<irq_data> data) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int pci_msi_prepare(Ptr<irq_domain> domain, Ptr<device> dev, int nvec,
      Ptr<@OriginalName("msi_alloc_info_t") irq_alloc_info> arg) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("pci_msi_register_fwnode_provider((struct fwnode_handle* (*)(struct device*))$arg1)")
  public static void pci_msi_register_fwnode_provider(Ptr<?> fn) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void pci_msi_set_enable(Ptr<pci_dev> dev, int enable) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int pci_msi_setup_msi_irqs(Ptr<pci_dev> dev, int nvec, int type) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void pci_msi_shutdown(Ptr<pci_dev> dev) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int pci_msi_supported(Ptr<pci_dev> dev, int nvec) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void pci_msi_teardown_msi_irqs(Ptr<pci_dev> dev) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void pci_msi_unmask_irq(Ptr<irq_data> data) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void pci_msi_update_mask(Ptr<msi_desc> desc, @Unsigned int clear,
      @Unsigned int set) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int pci_msi_vec_count(Ptr<pci_dev> dev) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("pci_msix_alloc_irq_at($arg1, $arg2, (const struct irq_affinity_desc*)$arg3)")
  public static msi_map pci_msix_alloc_irq_at(Ptr<pci_dev> dev, @Unsigned int index,
      Ptr<irq_affinity_desc> affdesc) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static boolean pci_msix_can_alloc_dyn(Ptr<pci_dev> dev) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void pci_msix_free_irq(Ptr<pci_dev> dev, msi_map map) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void pci_msix_init(Ptr<pci_dev> dev) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void pci_msix_prepare_desc(Ptr<irq_domain> domain,
      Ptr<@OriginalName("msi_alloc_info_t") irq_alloc_info> arg, Ptr<msi_desc> desc) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void pci_msix_shutdown(Ptr<pci_dev> dev) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int pci_msix_vec_count(Ptr<pci_dev> dev) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int pci_msix_write_tph_tag(Ptr<pci_dev> pdev, @Unsigned int index,
      @Unsigned short tag) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("pci_netmos_9900_setup($arg1, (const struct pciserial_board*)$arg2, $arg3, $arg4)")
  public static int pci_netmos_9900_setup(Ptr<serial_private> priv, Ptr<pciserial_board> board,
      Ptr<uart_8250_port> port, int idx) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int pci_netmos_init(Ptr<pci_dev> dev) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void pci_ni8420_exit(Ptr<pci_dev> dev) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int pci_ni8420_init(Ptr<pci_dev> dev) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void pci_ni8430_exit(Ptr<pci_dev> dev) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int pci_ni8430_init(Ptr<pci_dev> dev) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("pci_ni8430_setup($arg1, (const struct pciserial_board*)$arg2, $arg3, $arg4)")
  public static int pci_ni8430_setup(Ptr<serial_private> priv, Ptr<pciserial_board> board,
      Ptr<uart_8250_port> port, int idx) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void pci_no_aer() {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void pci_no_msi() {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void pci_no_tph() {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int pci_notify(Ptr<notifier_block> nb, @Unsigned long action, Ptr<?> data) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void pci_npem_create(Ptr<pci_dev> dev) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("pci_npem_init($arg1, (const struct npem_ops*)$arg2, $arg3, $arg4)")
  public static int pci_npem_init(Ptr<pci_dev> dev, Ptr<npem_ops> ops, int pos,
      @Unsigned int caps) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void pci_npem_remove(Ptr<pci_dev> dev) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int pci_num_vf(Ptr<pci_dev> dev) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int pci_numachip_init() {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("pci_omegapci_setup($arg1, (const struct pciserial_board*)$arg2, $arg3, $arg4)")
  public static int pci_omegapci_setup(Ptr<serial_private> priv, Ptr<pciserial_board> board,
      Ptr<uart_8250_port> port, int idx) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static @Unsigned int pci_oxsemi_tornado_get_divisor(Ptr<uart_port> port,
      @Unsigned int baud, Ptr<java.lang. @Unsigned Integer> frac) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int pci_oxsemi_tornado_init(Ptr<pci_dev> dev) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void pci_oxsemi_tornado_set_divisor(Ptr<uart_port> port, @Unsigned int baud,
      @Unsigned int quot, @Unsigned int quot_frac) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void pci_oxsemi_tornado_set_mctrl(Ptr<uart_port> port, @Unsigned int mctrl) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("pci_oxsemi_tornado_setup($arg1, (const struct pciserial_board*)$arg2, $arg3, $arg4)")
  public static int pci_oxsemi_tornado_setup(Ptr<serial_private> priv, Ptr<pciserial_board> board,
      Ptr<uart_8250_port> up, int idx) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int pci_p2pdma_add_resource(Ptr<pci_dev> pdev, int bar, @Unsigned long size,
      @Unsigned long offset) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int pci_p2pdma_distance_many(Ptr<pci_dev> provider, Ptr<Ptr<device>> clients,
      int num_clients, boolean verbose) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static @OriginalName("ssize_t") long pci_p2pdma_enable_show(String page,
      Ptr<pci_dev> p2p_dev, boolean use_p2pdma) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("pci_p2pdma_enable_store((const u8*)$arg1, $arg2, $arg3)")
  public static int pci_p2pdma_enable_store(String page, Ptr<Ptr<pci_dev>> p2p_dev,
      Ptr<java.lang. @OriginalName("bool") Boolean> use_p2pdma) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void pci_p2pdma_release(Ptr<?> data) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void pci_p2pdma_unmap_mappings(Ptr<?> data) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static Ptr<scatterlist> pci_p2pmem_alloc_sgl(Ptr<pci_dev> pdev,
      Ptr<java.lang. @Unsigned Integer> nents, @Unsigned int length) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static Ptr<pci_dev> pci_p2pmem_find_many(Ptr<Ptr<device>> clients, int num_clients) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void pci_p2pmem_free_sgl(Ptr<pci_dev> pdev, Ptr<scatterlist> sgl) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void pci_p2pmem_publish(Ptr<pci_dev> pdev, boolean publish) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static @Unsigned @OriginalName("pci_bus_addr_t") long pci_p2pmem_virt_to_bus(
      Ptr<pci_dev> pdev, Ptr<?> addr) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int pci_parse_mcfg(Ptr<acpi_table_header> header) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int pci_pasid_features(Ptr<pci_dev> pdev) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void pci_pasid_init(Ptr<pci_dev> pdev) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int pci_pasid_status(Ptr<pci_dev> pdev) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int pci_pasid_table_setup(Ptr<pci_dev> pdev, @Unsigned short alias, Ptr<?> data) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int pci_pasid_table_teardown(Ptr<pci_dev> pdev, @Unsigned short alias,
      Ptr<?> data) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static @Unsigned @OriginalName("phys_addr_t") long pci_pio_to_address(@Unsigned long pio) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int pci_platform_power_transition(Ptr<pci_dev> dev,
      @OriginalName("pci_power_t") int state) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void pci_plx9050_exit(Ptr<pci_dev> dev) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int pci_plx9050_init(Ptr<pci_dev> dev) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void pci_pm_complete(Ptr<device> dev) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int pci_pm_freeze(Ptr<device> dev) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int pci_pm_freeze_noirq(Ptr<device> dev) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void pci_pm_init(Ptr<pci_dev> dev) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void pci_pm_power_up_and_verify_state(Ptr<pci_dev> pci_dev) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int pci_pm_poweroff(Ptr<device> dev) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int pci_pm_poweroff_late(Ptr<device> dev) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int pci_pm_poweroff_noirq(Ptr<device> dev) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int pci_pm_prepare(Ptr<device> dev) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int pci_pm_reset(Ptr<pci_dev> dev, boolean probe) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int pci_pm_restore(Ptr<device> dev) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int pci_pm_restore_noirq(Ptr<device> dev) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int pci_pm_resume(Ptr<device> dev) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int pci_pm_resume_early(Ptr<device> dev) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int pci_pm_resume_noirq(Ptr<device> dev) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int pci_pm_runtime_get_sync(Ptr<pci_dev> pdev, Ptr<?> data) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int pci_pm_runtime_idle(Ptr<device> dev) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int pci_pm_runtime_put(Ptr<pci_dev> pdev, Ptr<?> data) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int pci_pm_runtime_resume(Ptr<device> dev) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int pci_pm_runtime_suspend(Ptr<device> dev) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int pci_pm_suspend(Ptr<device> dev) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int pci_pm_suspend_late(Ptr<device> dev) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int pci_pm_suspend_noirq(Ptr<device> dev) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int pci_pm_thaw(Ptr<device> dev) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int pci_pm_thaw_noirq(Ptr<device> dev) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void pci_pme_active(Ptr<pci_dev> dev, boolean enable) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static boolean pci_pme_capable(Ptr<pci_dev> dev, @OriginalName("pci_power_t") int state) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void pci_pme_list_scan(Ptr<work_struct> work) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void pci_pme_restore(Ptr<pci_dev> dev) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int pci_pme_wakeup(Ptr<pci_dev> dev, Ptr<?> pme_poll_reset) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void pci_pme_wakeup_bus(Ptr<pci_bus> bus) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void pci_post_fixup_toshiba_ohci1394(Ptr<pci_dev> dev) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int pci_power_up(Ptr<pci_dev> dev) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static boolean pci_pr3_present(Ptr<pci_dev> pdev) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void pci_pre_fixup_toshiba_ohci1394(Ptr<pci_dev> dev) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int pci_prepare_ats(Ptr<pci_dev> dev, int ps) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void pci_prepare_next_assign_round(Ptr<list_head> fail_head, int tried_times,
      release_type rel_type) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int pci_prepare_to_sleep(Ptr<pci_dev> dev) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int pci_prg_resp_pasid_required(Ptr<pci_dev> pdev) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void pci_pri_init(Ptr<pci_dev> pdev) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static boolean pci_pri_supported(Ptr<pci_dev> pdev) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int pci_primary_epc_epf_link(Ptr<config_item> epf_item, Ptr<config_item> epc_item) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void pci_primary_epc_epf_unlink(Ptr<config_item> epc_item,
      Ptr<config_item> epf_item) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void pci_print_aer(Ptr<pci_dev> dev, int aer_severity,
      Ptr<aer_capability_regs> aer) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int pci_probe_reset_bus(Ptr<pci_bus> bus) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int pci_probe_reset_slot(Ptr<pci_slot> slot) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int pci_proc_attach_device(Ptr<pci_dev> dev) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int pci_proc_detach_bus(Ptr<pci_bus> bus) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int pci_proc_detach_device(Ptr<pci_dev> dev) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int pci_proc_init() {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void pci_ptm_init(Ptr<pci_dev> dev) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void pci_put_host_bridge_device(Ptr<device> dev) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int pci_quatech_init(Ptr<pci_dev> dev) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("pci_quatech_setup($arg1, (const struct pciserial_board*)$arg2, $arg3, $arg4)")
  public static int pci_quatech_setup(Ptr<serial_private> priv, Ptr<pciserial_board> board,
      Ptr<uart_8250_port> port, int idx) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int pci_quirk_al_acs(Ptr<pci_dev> dev, @Unsigned short acs_flags) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int pci_quirk_amd_sb_acs(Ptr<pci_dev> dev, @Unsigned short acs_flags) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int pci_quirk_brcm_acs(Ptr<pci_dev> dev, @Unsigned short acs_flags) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int pci_quirk_cavium_acs(Ptr<pci_dev> dev, @Unsigned short acs_flags) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int pci_quirk_disable_intel_spt_pch_acs_redir(Ptr<pci_dev> dev) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int pci_quirk_enable_intel_pch_acs(Ptr<pci_dev> dev) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int pci_quirk_enable_intel_spt_pch_acs(Ptr<pci_dev> dev) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int pci_quirk_intel_pch_acs(Ptr<pci_dev> dev, @Unsigned short acs_flags) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int pci_quirk_intel_spt_pch_acs(Ptr<pci_dev> dev, @Unsigned short acs_flags) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static boolean pci_quirk_intel_spt_pch_acs_match(Ptr<pci_dev> dev) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int pci_quirk_loongson_acs(Ptr<pci_dev> dev, @Unsigned short acs_flags) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int pci_quirk_mf_endpoint_acs(Ptr<pci_dev> dev, @Unsigned short acs_flags) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void pci_quirk_nvidia_tegra_disable_rp_msi(Ptr<pci_dev> dev) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int pci_quirk_nxp_rp_acs(Ptr<pci_dev> dev, @Unsigned short acs_flags) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int pci_quirk_qcom_rp_acs(Ptr<pci_dev> dev, @Unsigned short acs_flags) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int pci_quirk_rciep_acs(Ptr<pci_dev> dev, @Unsigned short acs_flags) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int pci_quirk_wangxun_nic_acs(Ptr<pci_dev> dev, @Unsigned short acs_flags) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int pci_quirk_xgene_acs(Ptr<pci_dev> dev, @Unsigned short acs_flags) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int pci_quirk_zhaoxin_pcie_ports_acs(Ptr<pci_dev> dev, @Unsigned short acs_flags) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void pci_rcec_exit(Ptr<pci_dev> dev) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void pci_rcec_init(Ptr<pci_dev> dev) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int pci_read(Ptr<pci_bus> bus, @Unsigned int devfn, int where, int size,
      Ptr<java.lang. @Unsigned Integer> value) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void pci_read_bridge_bases(Ptr<pci_bus> child) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void pci_read_bridge_io(Ptr<pci_dev> dev, Ptr<resource> res, boolean log) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void pci_read_bridge_mmio(Ptr<pci_dev> dev, Ptr<resource> res, boolean log) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void pci_read_bridge_mmio_pref(Ptr<pci_dev> dev, Ptr<resource> res, boolean log) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void pci_read_bridge_windows(Ptr<pci_dev> bridge) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("pci_read_config($arg1, $arg2, (const struct bin_attribute*)$arg3, $arg4, $arg5, $arg6)")
  public static @OriginalName("ssize_t") long pci_read_config(Ptr<file> filp, Ptr<kobject> kobj,
      Ptr<bin_attribute> bin_attr, String buf, @OriginalName("loff_t") long off,
      @Unsigned long count) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("pci_read_config_byte((const struct pci_dev*)$arg1, $arg2, $arg3)")
  public static int pci_read_config_byte(Ptr<pci_dev> dev, int where,
      Ptr<java.lang.Character> val) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("pci_read_config_dword((const struct pci_dev*)$arg1, $arg2, $arg3)")
  public static int pci_read_config_dword(Ptr<pci_dev> dev, int where,
      Ptr<java.lang. @Unsigned Integer> val) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("pci_read_config_word((const struct pci_dev*)$arg1, $arg2, $arg3)")
  public static int pci_read_config_word(Ptr<pci_dev> dev, int where,
      Ptr<java.lang. @Unsigned Short> val) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void pci_read_irq(Ptr<pci_dev> dev) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("pci_read_resource_io($arg1, $arg2, (const struct bin_attribute*)$arg3, $arg4, $arg5, $arg6)")
  public static @OriginalName("ssize_t") long pci_read_resource_io(Ptr<file> filp,
      Ptr<kobject> kobj, Ptr<bin_attribute> attr, String buf, @OriginalName("loff_t") long off,
      @Unsigned long count) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("pci_read_rom($arg1, $arg2, (const struct bin_attribute*)$arg3, $arg4, $arg5, $arg6)")
  public static @OriginalName("ssize_t") long pci_read_rom(Ptr<file> filp, Ptr<kobject> kobj,
      Ptr<bin_attribute> bin_attr, String buf, @OriginalName("loff_t") long off,
      @Unsigned long count) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static @OriginalName("ssize_t") long pci_read_vpd(Ptr<pci_dev> dev,
      @OriginalName("loff_t") long pos, @Unsigned long count, Ptr<?> buf) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static @OriginalName("ssize_t") long pci_read_vpd_any(Ptr<pci_dev> dev,
      @OriginalName("loff_t") long pos, @Unsigned long count, Ptr<?> buf) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static Ptr<pci_dev> pci_real_dma_dev(Ptr<pci_dev> dev) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void pci_realloc_get_opt(String str) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int pci_realloc_setup_params() {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int pci_reassign_bridge_resources(Ptr<pci_dev> bridge, @Unsigned long type) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int pci_reassign_resource(Ptr<pci_dev> dev, int resno,
      @Unsigned @OriginalName("resource_size_t") long addsize,
      @Unsigned @OriginalName("resource_size_t") long min_align) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void pci_reassigndev_resource_alignment(Ptr<pci_dev> dev) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int pci_rebar_find_pos(Ptr<pci_dev> pdev, int bar) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int pci_rebar_get_current_size(Ptr<pci_dev> pdev, int bar) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static @Unsigned int pci_rebar_get_possible_sizes(Ptr<pci_dev> pdev, int bar) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void pci_rebar_init(Ptr<pci_dev> pdev) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int pci_rebar_set_size(Ptr<pci_dev> pdev, int bar, int size) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int pci_reenable_device(Ptr<pci_dev> dev) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void pci_refresh_power_state(Ptr<pci_dev> dev) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int pci_register_host_bridge(Ptr<pci_host_bridge> bridge) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("pci_register_io_range((const struct fwnode_handle*)$arg1, $arg2, $arg3)")
  public static int pci_register_io_range(Ptr<fwnode_handle> fwnode,
      @Unsigned @OriginalName("phys_addr_t") long addr,
      @Unsigned @OriginalName("resource_size_t") long size) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void pci_register_set_vga_state(@OriginalName("arch_set_vga_state_t") Ptr<?> func) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void pci_release_dev(Ptr<device> dev) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void pci_release_host_bridge_dev(Ptr<device> dev) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void pci_release_region(Ptr<pci_dev> pdev, int bar) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void pci_release_regions(Ptr<pci_dev> pdev) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void pci_release_resource(Ptr<pci_dev> dev, int resno) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void pci_release_selected_regions(Ptr<pci_dev> pdev, int bars) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("pci_remap_iospace((const struct resource*)$arg1, $arg2)")
  public static int pci_remap_iospace(Ptr<resource> res,
      @Unsigned @OriginalName("phys_addr_t") long phys_addr) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void pci_remove_bus(Ptr<pci_bus> bus) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void pci_remove_bus_device(Ptr<pci_dev> dev) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void pci_remove_resource_files(Ptr<pci_dev> pdev) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void pci_remove_root_bus(Ptr<pci_bus> bus) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void pci_remove_sysfs_dev_files(Ptr<pci_dev> pdev) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void pci_request_acs() {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("pci_request_irq($arg1, $arg2, $arg3, $arg4, $arg5, (const u8*)$arg6, $arg7_)")
  public static int pci_request_irq(Ptr<pci_dev> dev, @Unsigned int nr,
      @OriginalName("irq_handler_t") Ptr<?> handler,
      @OriginalName("irq_handler_t") Ptr<?> thread_fn, Ptr<?> dev_id, String fmt,
      java.lang.Object... param6) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("pci_request_region($arg1, $arg2, (const u8*)$arg3)")
  public static int pci_request_region(Ptr<pci_dev> pdev, int bar, String name) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("pci_request_regions($arg1, (const u8*)$arg2)")
  public static int pci_request_regions(Ptr<pci_dev> pdev, String name) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("pci_request_regions_exclusive($arg1, (const u8*)$arg2)")
  public static int pci_request_regions_exclusive(Ptr<pci_dev> pdev, String name) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("pci_request_selected_regions($arg1, $arg2, (const u8*)$arg3)")
  public static int pci_request_selected_regions(Ptr<pci_dev> pdev, int bars, String name) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("pci_request_selected_regions_exclusive($arg1, $arg2, (const u8*)$arg3)")
  public static int pci_request_selected_regions_exclusive(Ptr<pci_dev> pdev, int bars,
      String name) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static boolean pci_required_resource_failed(Ptr<list_head> fail_head,
      @Unsigned long type) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static @Unsigned int pci_rescan_bus(Ptr<pci_bus> bus) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static @Unsigned int pci_rescan_bus_bridge_resize(Ptr<pci_dev> bridge) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int pci_reset_bus(Ptr<pci_dev> pdev) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int pci_reset_bus_function(Ptr<pci_dev> dev, boolean probe) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int pci_reset_function(Ptr<pci_dev> dev) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int pci_reset_function_locked(Ptr<pci_dev> dev) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int pci_reset_hotplug_slot(Ptr<hotplug_slot> hotplug, boolean probe) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int pci_reset_pri(Ptr<pci_dev> pdev) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void pci_reset_secondary_bus(Ptr<pci_dev> dev) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static boolean pci_reset_supported(Ptr<pci_dev> dev) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int pci_resize_resource(Ptr<pci_dev> dev, int resno, int size) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void pci_resize_resource_set_size(Ptr<pci_dev> dev, int resno, int size) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int pci_resource_alignment_sysfs_init() {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("pci_resource_is_optional((const struct pci_dev*)$arg1, $arg2)")
  public static boolean pci_resource_is_optional(Ptr<pci_dev> dev, int resno) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("((const u8*)pci_resource_name($arg1, $arg2))")
  public static String pci_resource_name(Ptr<pci_dev> dev, @Unsigned int i) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("pci_resource_to_user((const struct pci_dev*)$arg1, $arg2, (const struct resource*)$arg3, $arg4, $arg5)")
  public static void pci_resource_to_user(Ptr<pci_dev> dev, int bar, Ptr<resource> rsrc,
      Ptr<java.lang. @Unsigned @OriginalName("resource_size_t") Long> start,
      Ptr<java.lang. @Unsigned @OriginalName("resource_size_t") Long> end) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void pci_restore_aer_state(Ptr<pci_dev> dev) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void pci_restore_aspm_l1ss_state(Ptr<pci_dev> pdev) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void pci_restore_ats_state(Ptr<pci_dev> dev) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void pci_restore_config_space_range(Ptr<pci_dev> pdev, int start, int end,
      int retry, boolean force) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void pci_restore_dpc_state(Ptr<pci_dev> dev) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void pci_restore_iov_state(Ptr<pci_dev> dev) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void pci_restore_ltr_state(Ptr<pci_dev> dev) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void pci_restore_msi_state(Ptr<pci_dev> dev) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void pci_restore_pasid_state(Ptr<pci_dev> pdev) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void pci_restore_pri_state(Ptr<pci_dev> pdev) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void pci_restore_ptm_state(Ptr<pci_dev> dev) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void pci_restore_rebar_state(Ptr<pci_dev> pdev) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void pci_restore_state(Ptr<pci_dev> dev) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void pci_restore_tph_state(Ptr<pci_dev> pdev) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void pci_restore_vc_state(Ptr<pci_dev> dev) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void pci_resume_bus(Ptr<pci_bus> bus) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int pci_resume_one(Ptr<pci_dev> pci_dev, Ptr<?> ign) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void pci_resume_ptm(Ptr<pci_dev> dev) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void pci_root_bus_distribute_available_resources(Ptr<pci_bus> bus,
      Ptr<list_head> add_list) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("pci_sanity_check((const struct pci_raw_ops*)$arg1)")
  public static int pci_sanity_check(Ptr<pci_raw_ops> o) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void pci_save_aer_state(Ptr<pci_dev> dev) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void pci_save_aspm_l1ss_state(Ptr<pci_dev> pdev) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void pci_save_dpc_state(Ptr<pci_dev> dev) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void pci_save_ltr_state(Ptr<pci_dev> dev) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void pci_save_ptm_state(Ptr<pci_dev> dev) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int pci_save_state(Ptr<pci_dev> dev) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void pci_save_tph_state(Ptr<pci_dev> pdev) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int pci_save_vc_state(Ptr<pci_dev> dev) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int pci_scan_bridge(Ptr<pci_bus> bus, Ptr<pci_dev> dev, int max, int pass) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int pci_scan_bridge_extend(Ptr<pci_bus> bus, Ptr<pci_dev> dev, int max,
      @Unsigned int available_buses, int pass) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static Ptr<pci_bus> pci_scan_bus(int bus, Ptr<pci_ops> ops, Ptr<?> sysdata) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static @Unsigned int pci_scan_child_bus(Ptr<pci_bus> bus) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static @Unsigned int pci_scan_child_bus_extend(Ptr<pci_bus> bus,
      @Unsigned int available_buses) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static Ptr<pci_bus> pci_scan_root_bus(Ptr<device> parent, int bus, Ptr<pci_ops> ops,
      Ptr<?> sysdata, Ptr<list_head> resources) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int pci_scan_root_bus_bridge(Ptr<pci_host_bridge> bridge) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static Ptr<pci_dev> pci_scan_single_device(Ptr<pci_bus> bus, int devfn) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int pci_scan_slot(Ptr<pci_bus> bus, int devfn) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int pci_secondary_epc_epf_link(Ptr<config_item> epf_item,
      Ptr<config_item> epc_item) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void pci_secondary_epc_epf_unlink(Ptr<config_item> epc_item,
      Ptr<config_item> epf_item) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int pci_select_bars(Ptr<pci_dev> dev, @Unsigned long flags) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static Ptr<?> pci_seq_next(Ptr<seq_file> m, Ptr<?> v,
      Ptr<java.lang. @OriginalName("loff_t") Long> pos) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static Ptr<?> pci_seq_start(Ptr<seq_file> m,
      Ptr<java.lang. @OriginalName("loff_t") Long> pos) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void pci_seq_stop(Ptr<seq_file> m, Ptr<?> v) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void pci_serr_error(char reason, Ptr<pt_regs> regs) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void pci_set_acpi_fwnode(Ptr<pci_dev> dev) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void pci_set_bus_msi_domain(Ptr<pci_bus> bus) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void pci_set_bus_speed(Ptr<pci_bus> bus) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int pci_set_cacheline_size(Ptr<pci_dev> dev) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("pci_set_host_bridge_release($arg1, (void (*)(struct pci_host_bridge*))$arg2, $arg3)")
  public static void pci_set_host_bridge_release(Ptr<pci_host_bridge> bridge, Ptr<?> release_fn,
      Ptr<?> release_data) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int pci_set_low_power_state(Ptr<pci_dev> dev,
      @OriginalName("pci_power_t") int state, boolean locked) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void pci_set_master(Ptr<pci_dev> dev) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int pci_set_mwi(Ptr<pci_dev> dev) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int pci_set_pcie_reset_state(Ptr<pci_dev> dev, pcie_reset_state state) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int pci_set_power_state(Ptr<pci_dev> dev, @OriginalName("pci_power_t") int state) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int pci_set_power_state_locked(Ptr<pci_dev> dev,
      @OriginalName("pci_power_t") int state) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int pci_set_vga_state(Ptr<pci_dev> dev, boolean decode, @Unsigned int command_bits,
      @Unsigned int flags) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int pci_setup(String str) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void pci_setup_bridge_io(Ptr<pci_dev> bridge) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void pci_setup_bridge_mmio(Ptr<pci_dev> bridge) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void pci_setup_bridge_mmio_pref(Ptr<pci_dev> bridge) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void pci_setup_cardbus(Ptr<pci_bus> bus) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int pci_setup_device(Ptr<pci_dev> dev) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static boolean pci_setup_msi_device_domain(Ptr<pci_dev> pdev, @Unsigned int hwsize) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static boolean pci_setup_msix_device_domain(Ptr<pci_dev> pdev, @Unsigned int hwsize) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void pci_siemens_interrupt_controller(Ptr<pci_dev> dev) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int pci_siig_init(Ptr<pci_dev> dev) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("pci_siig_setup($arg1, (const struct pciserial_board*)$arg2, $arg3, $arg4)")
  public static int pci_siig_setup(Ptr<serial_private> priv, Ptr<pciserial_board> board,
      Ptr<uart_8250_port> port, int idx) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static @OriginalName("ssize_t") long pci_slot_attr_show(Ptr<kobject> kobj,
      Ptr<attribute> attr, String buf) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("pci_slot_attr_store($arg1, $arg2, (const u8*)$arg3, $arg4)")
  public static @OriginalName("ssize_t") long pci_slot_attr_store(Ptr<kobject> kobj,
      Ptr<attribute> attr, String buf, @Unsigned long len) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int pci_slot_init() {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void pci_slot_release(Ptr<kobject> kobj) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int pci_slot_reset(Ptr<pci_slot> slot, boolean probe) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void pci_slot_unlock(Ptr<pci_slot> slot) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("pci_sort_bf_cmp((const struct device*)$arg1, (const struct device*)$arg2)")
  public static int pci_sort_bf_cmp(Ptr<device> d_a, Ptr<device> d_b) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void pci_sort_breadthfirst() {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static @Unsigned @OriginalName("resource_size_t") long pci_specified_resource_alignment(
      Ptr<pci_dev> dev, Ptr<java.lang. @OriginalName("bool") Boolean> resize) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("((const u8*)pci_speed_string($arg1))")
  public static String pci_speed_string(pci_bus_speed speed) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int pci_sriov_configure_simple(Ptr<pci_dev> dev, int nr_virtfn) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int pci_sriov_get_totalvfs(Ptr<pci_dev> dev) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static @Unsigned @OriginalName("resource_size_t") long pci_sriov_resource_alignment(
      Ptr<pci_dev> dev, int resno) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int pci_sriov_set_totalvfs(Ptr<pci_dev> dev, @Unsigned short numvfs) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int pci_status_get_and_clear_errors(Ptr<pci_dev> pdev) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void pci_std_update_resource(Ptr<pci_dev> dev, int resno) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void pci_stop_and_remove_bus_device(Ptr<pci_dev> dev) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void pci_stop_and_remove_bus_device_locked(Ptr<pci_dev> dev) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void pci_stop_bus_device(Ptr<pci_dev> dev) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void pci_stop_root_bus(Ptr<pci_bus> bus) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static Ptr<pci_saved_state> pci_store_saved_state(Ptr<pci_dev> dev) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int pci_subsys_init() {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("pci_sunix_setup($arg1, (const struct pciserial_board*)$arg2, $arg3, $arg4)")
  public static int pci_sunix_setup(Ptr<serial_private> priv, Ptr<pciserial_board> board,
      Ptr<uart_8250_port> port, int idx) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void pci_suspend_ptm(Ptr<pci_dev> dev) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("pci_swizzle_interrupt_pin((const struct pci_dev*)$arg1, $arg2)")
  public static char pci_swizzle_interrupt_pin(Ptr<pci_dev> dev, char pin) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int pci_sysfs_init() {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static @OriginalName("pci_power_t") int pci_target_state(Ptr<pci_dev> dev,
      boolean wakeup) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("pci_test_config_bits($arg1, (const struct pci_bits*)$arg2)")
  public static int pci_test_config_bits(Ptr<pci_dev> pdev, Ptr<pci_bits> bits) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int pci_timedia_init(Ptr<pci_dev> dev) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int pci_timedia_probe(Ptr<pci_dev> dev) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("pci_timedia_setup($arg1, (const struct pciserial_board*)$arg2, $arg3, $arg4)")
  public static int pci_timedia_setup(Ptr<serial_private> priv, Ptr<pciserial_board> board,
      Ptr<uart_8250_port> port, int idx) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void pci_tph_init(Ptr<pci_dev> pdev) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int pci_try_reset_function(Ptr<pci_dev> dev) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int pci_try_set_mwi(Ptr<pci_dev> dev) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("pci_uevent((const struct device*)$arg1, $arg2)")
  public static int pci_uevent(Ptr<device> dev, Ptr<kobj_uevent_env> env) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void pci_uevent_ers(Ptr<pci_dev> pdev, pci_ers_result err_type) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void pci_unlock_rescan_remove() {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void pci_unmap_biosrom(Ptr<?> image) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void pci_unmap_iospace(Ptr<resource> res) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void pci_unmap_rom(Ptr<pci_dev> pdev, Ptr<?> rom) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void pci_unregister_driver(Ptr<pci_driver> drv) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void pci_update_current_state(Ptr<pci_dev> dev,
      @OriginalName("pci_power_t") int state) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void pci_update_resource(Ptr<pci_dev> dev, int resno) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static Ptr<pci_dev> pci_upstream_ptm(Ptr<pci_dev> dev) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int pci_user_read_config_byte(Ptr<pci_dev> dev, int pos,
      Ptr<java.lang.Character> val) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int pci_user_read_config_dword(Ptr<pci_dev> dev, int pos,
      Ptr<java.lang. @Unsigned Integer> val) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int pci_user_read_config_word(Ptr<pci_dev> dev, int pos,
      Ptr<java.lang. @Unsigned Short> val) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int pci_user_write_config_byte(Ptr<pci_dev> dev, int pos, char val) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int pci_user_write_config_dword(Ptr<pci_dev> dev, int pos, @Unsigned int val) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int pci_user_write_config_word(Ptr<pci_dev> dev, int pos, @Unsigned short val) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int pci_vc_do_save_buffer(Ptr<pci_dev> dev, int pos,
      Ptr<pci_cap_saved_state> save_state, boolean save) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void pci_vc_enable(Ptr<pci_dev> dev, int pos, int res) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void pci_vf_drivers_autoprobe(Ptr<pci_dev> dev, boolean auto_probe) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int pci_vfs_assigned(Ptr<pci_dev> dev) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static Ptr<?> pci_vpd_alloc(Ptr<pci_dev> dev, Ptr<java.lang. @Unsigned Integer> size) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static boolean pci_vpd_available(Ptr<pci_dev> dev, boolean check_size) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("pci_vpd_check_csum((const void*)$arg1, $arg2)")
  public static int pci_vpd_check_csum(Ptr<?> buf, @Unsigned int len) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("pci_vpd_find_id_string((const u8*)$arg1, $arg2, $arg3)")
  public static int pci_vpd_find_id_string(Ptr<java.lang.Character> buf, @Unsigned int len,
      Ptr<java.lang. @Unsigned Integer> size) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("pci_vpd_find_ro_info_keyword((const void*)$arg1, $arg2, (const u8*)$arg3, $arg4)")
  public static int pci_vpd_find_ro_info_keyword(Ptr<?> buf, @Unsigned int len, String kw,
      Ptr<java.lang. @Unsigned Integer> size) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void pci_vpd_init(Ptr<pci_dev> dev) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static @OriginalName("ssize_t") long pci_vpd_read(Ptr<pci_dev> dev,
      @OriginalName("loff_t") long pos, @Unsigned long count, Ptr<?> arg, boolean check_size) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int pci_vpd_wait(Ptr<pci_dev> dev, boolean set) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("pci_vpd_write($arg1, $arg2, $arg3, (const void*)$arg4, $arg5)")
  public static @OriginalName("ssize_t") long pci_vpd_write(Ptr<pci_dev> dev,
      @OriginalName("loff_t") long pos, @Unsigned long count, Ptr<?> arg, boolean check_size) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void pci_wait_cfg(Ptr<pci_dev> dev) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int pci_wait_for_pending(Ptr<pci_dev> dev, int pos, @Unsigned short mask) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int pci_wait_for_pending_transaction(Ptr<pci_dev> dev) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int pci_wake_from_d3(Ptr<pci_dev> dev, boolean enable) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("pci_walk_bus($arg1, (int (*)(struct pci_dev*, void*))$arg2, $arg3)")
  public static void pci_walk_bus(Ptr<pci_bus> top, Ptr<?> cb, Ptr<?> userdata) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("pci_walk_bus_locked($arg1, (int (*)(struct pci_dev*, void*))$arg2, $arg3)")
  public static void pci_walk_bus_locked(Ptr<pci_bus> top, Ptr<?> cb, Ptr<?> userdata) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("pci_wch_ch353_setup($arg1, (const struct pciserial_board*)$arg2, $arg3, $arg4)")
  public static int pci_wch_ch353_setup(Ptr<serial_private> priv, Ptr<pciserial_board> board,
      Ptr<uart_8250_port> port, int idx) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("pci_wch_ch355_setup($arg1, (const struct pciserial_board*)$arg2, $arg3, $arg4)")
  public static int pci_wch_ch355_setup(Ptr<serial_private> priv, Ptr<pciserial_board> board,
      Ptr<uart_8250_port> port, int idx) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void pci_wch_ch38x_exit(Ptr<pci_dev> dev) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int pci_wch_ch38x_init(Ptr<pci_dev> dev) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("pci_wch_ch38x_setup($arg1, (const struct pciserial_board*)$arg2, $arg3, $arg4)")
  public static int pci_wch_ch38x_setup(Ptr<serial_private> priv, Ptr<pciserial_board> board,
      Ptr<uart_8250_port> port, int idx) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int pci_write(Ptr<pci_bus> bus, @Unsigned int devfn, int where, int size,
      @Unsigned int value) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("pci_write_config($arg1, $arg2, (const struct bin_attribute*)$arg3, $arg4, $arg5, $arg6)")
  public static @OriginalName("ssize_t") long pci_write_config(Ptr<file> filp, Ptr<kobject> kobj,
      Ptr<bin_attribute> bin_attr, String buf, @OriginalName("loff_t") long off,
      @Unsigned long count) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("pci_write_config_byte((const struct pci_dev*)$arg1, $arg2, $arg3)")
  public static int pci_write_config_byte(Ptr<pci_dev> dev, int where, char val) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("pci_write_config_dword((const struct pci_dev*)$arg1, $arg2, $arg3)")
  public static int pci_write_config_dword(Ptr<pci_dev> dev, int where, @Unsigned int val) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("pci_write_config_word((const struct pci_dev*)$arg1, $arg2, $arg3)")
  public static int pci_write_config_word(Ptr<pci_dev> dev, int where, @Unsigned short val) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void pci_write_msi_msg(@Unsigned int irq, Ptr<msi_msg> msg) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("pci_write_resource_io($arg1, $arg2, (const struct bin_attribute*)$arg3, $arg4, $arg5, $arg6)")
  public static @OriginalName("ssize_t") long pci_write_resource_io(Ptr<file> filp,
      Ptr<kobject> kobj, Ptr<bin_attribute> attr, String buf, @OriginalName("loff_t") long off,
      @Unsigned long count) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("pci_write_rom($arg1, $arg2, (const struct bin_attribute*)$arg3, $arg4, $arg5, $arg6)")
  public static @OriginalName("ssize_t") long pci_write_rom(Ptr<file> filp, Ptr<kobject> kobj,
      Ptr<bin_attribute> bin_attr, String buf, @OriginalName("loff_t") long off,
      @Unsigned long count) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("pci_write_vpd($arg1, $arg2, $arg3, (const void*)$arg4)")
  public static @OriginalName("ssize_t") long pci_write_vpd(Ptr<pci_dev> dev,
      @OriginalName("loff_t") long pos, @Unsigned long count, Ptr<?> buf) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("pci_write_vpd_any($arg1, $arg2, $arg3, (const void*)$arg4)")
  public static @OriginalName("ssize_t") long pci_write_vpd_any(Ptr<pci_dev> dev,
      @OriginalName("loff_t") long pos, @Unsigned long count, Ptr<?> buf) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int pci_xen_hvm_init() {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int pci_xen_init() {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int pci_xen_initial_domain() {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int pci_xircom_init(Ptr<pci_dev> dev) {
    throw new MethodIsBPFRelatedFunction();
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct pci_device_id"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class pci_device_id extends Struct {
    public @Unsigned int vendor;

    public @Unsigned int device;

    public @Unsigned int subvendor;

    public @Unsigned int subdevice;

    public @Unsigned int _class;

    public @Unsigned int class_mask;

    public @Unsigned @OriginalName("kernel_ulong_t") long driver_data;

    public @Unsigned int override_only;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct pci_slot"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class pci_slot extends Struct {
    public Ptr<pci_bus> bus;

    public list_head list;

    public Ptr<hotplug_slot> hotplug;

    public char number;

    public kobject kobj;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct pci_bus"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class pci_bus extends Struct {
    public list_head node;

    public Ptr<pci_bus> parent;

    public list_head children;

    public list_head devices;

    public Ptr<pci_dev> self;

    public list_head slots;

    public Ptr<resource> @Size(4) [] resource;

    public list_head resources;

    public resource busn_res;

    public Ptr<pci_ops> ops;

    public Ptr<?> sysdata;

    public Ptr<proc_dir_entry> procdir;

    public char number;

    public char primary;

    public char max_bus_speed;

    public char cur_bus_speed;

    public char @Size(48) [] name;

    public @Unsigned short bridge_ctl;

    public @Unsigned @OriginalName("pci_bus_flags_t") short bus_flags;

    public Ptr<device> bridge;

    public device dev;

    public Ptr<bin_attribute> legacy_io;

    public Ptr<bin_attribute> legacy_mem;

    public @Unsigned int is_added;

    public @Unsigned int unsafe_warn;

    public @Unsigned int flit_mode;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct pci_vpd"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class pci_vpd extends Struct {
    public mutex lock;

    public @Unsigned int len;

    public char cap;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct pci_dev"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class pci_dev extends Struct {
    public list_head bus_list;

    public Ptr<pci_bus> bus;

    public Ptr<pci_bus> subordinate;

    public Ptr<?> sysdata;

    public Ptr<proc_dir_entry> procent;

    public Ptr<pci_slot> slot;

    public @Unsigned int devfn;

    public @Unsigned short vendor;

    public @Unsigned short device;

    public @Unsigned short subsystem_vendor;

    public @Unsigned short subsystem_device;

    public @Unsigned int _class;

    public char revision;

    public char hdr_type;

    public @Unsigned short aer_cap;

    public Ptr<aer_info> aer_info;

    public Ptr<rcec_ea> rcec_ea;

    public Ptr<pci_dev> rcec;

    public @Unsigned int devcap;

    public @Unsigned short rebar_cap;

    public char pcie_cap;

    public char msi_cap;

    public char msix_cap;

    public char pcie_mpss;

    public char rom_base_reg;

    public char pin;

    public @Unsigned short pcie_flags_reg;

    public Ptr<java.lang. @Unsigned Long> dma_alias_mask;

    public Ptr<pci_driver> driver;

    public @Unsigned long dma_mask;

    public device_dma_parameters dma_parms;

    public @OriginalName("pci_power_t") int current_state;

    public char pm_cap;

    public @Unsigned int pme_support;

    public @Unsigned int pme_poll;

    public @Unsigned int pinned;

    public @Unsigned int config_rrs_sv;

    public @Unsigned int imm_ready;

    public @Unsigned int d1_support;

    public @Unsigned int d2_support;

    public @Unsigned int no_d1d2;

    public @Unsigned int no_d3cold;

    public @Unsigned int bridge_d3;

    public @Unsigned int d3cold_allowed;

    public @Unsigned int mmio_always_on;

    public @Unsigned int wakeup_prepared;

    public @Unsigned int skip_bus_pm;

    public @Unsigned int ignore_hotplug;

    public @Unsigned int hotplug_user_indicators;

    public @Unsigned int clear_retrain_link;

    public @Unsigned int d3hot_delay;

    public @Unsigned int d3cold_delay;

    public @Unsigned short l1ss;

    public Ptr<pcie_link_state> link_state;

    public @Unsigned int ltr_path;

    public @Unsigned int pasid_no_tlp;

    public @Unsigned int eetlp_prefix_max;

    public @Unsigned @OriginalName("pci_channel_state_t") int error_state;

    public device dev;

    public int cfg_size;

    public @Unsigned int irq;

    public resource @Size(17) [] resource;

    public resource driver_exclusive_resource;

    public @Unsigned int transparent;

    public @Unsigned int io_window;

    public @Unsigned int pref_window;

    public @Unsigned int pref_64_window;

    public @Unsigned int multifunction;

    public @Unsigned int is_busmaster;

    public @Unsigned int no_msi;

    public @Unsigned int no_64bit_msi;

    public @Unsigned int block_cfg_access;

    public @Unsigned int broken_parity_status;

    public @Unsigned int irq_reroute_variant;

    public @Unsigned int msi_enabled;

    public @Unsigned int msix_enabled;

    public @Unsigned int ari_enabled;

    public @Unsigned int ats_enabled;

    public @Unsigned int pasid_enabled;

    public @Unsigned int pri_enabled;

    public @Unsigned int tph_enabled;

    public @Unsigned int is_managed;

    public @Unsigned int is_msi_managed;

    public @Unsigned int needs_freset;

    public @Unsigned int state_saved;

    public @Unsigned int is_physfn;

    public @Unsigned int is_virtfn;

    public @Unsigned int is_hotplug_bridge;

    public @Unsigned int is_pciehp;

    public @Unsigned int shpc_managed;

    public @Unsigned int is_thunderbolt;

    public @Unsigned int untrusted;

    public @Unsigned int external_facing;

    public @Unsigned int broken_intx_masking;

    public @Unsigned int io_window_1k;

    public @Unsigned int irq_managed;

    public @Unsigned int non_compliant_bars;

    public @Unsigned int is_probed;

    public @Unsigned int link_active_reporting;

    public @Unsigned int no_vf_scan;

    public @Unsigned int no_command_memory;

    public @Unsigned int rom_bar_overlap;

    public @Unsigned int rom_attr_enabled;

    public @Unsigned int non_mappable_bars;

    public @Unsigned int aspm_os_control;

    public @Unsigned @OriginalName("pci_dev_flags_t") short dev_flags;

    public atomic_t enable_cnt;

    public @OriginalName("spinlock_t") spinlock pcie_cap_lock;

    public @Unsigned int @Size(16) [] saved_config_space;

    public hlist_head saved_cap_space;

    public Ptr<bin_attribute> @Size(17) [] res_attr;

    public Ptr<bin_attribute> @Size(17) [] res_attr_wc;

    public @Unsigned int broken_cmd_compl;

    public @Unsigned short ptm_cap;

    public @Unsigned int ptm_root;

    public @Unsigned int ptm_enabled;

    public char ptm_granularity;

    public Ptr<?> msix_base;

    public @OriginalName("raw_spinlock_t") raw_spinlock msi_lock;

    public pci_vpd vpd;

    public @Unsigned short dpc_cap;

    public @Unsigned int dpc_rp_extensions;

    public char dpc_rp_log_size;

    public Ptr<pcie_bwctrl_data> link_bwctrl;

    @InlineUnion(4792)
    public Ptr<pci_sriov> sriov;

    @InlineUnion(4792)
    public Ptr<pci_dev> physfn;

    public @Unsigned short ats_cap;

    public char ats_stu;

    public @Unsigned short pri_cap;

    public @Unsigned int pri_reqs_alloc;

    public @Unsigned int pasid_required;

    public @Unsigned short pasid_cap;

    public @Unsigned short pasid_features;

    public Ptr<pci_p2pdma> p2pdma;

    public xarray doe_mbs;

    public Ptr<npem> npem;

    public @Unsigned short acs_cap;

    public char supported_speeds;

    public @Unsigned @OriginalName("phys_addr_t") long rom;

    public @Unsigned long romlen;

    public String driver_override;

    public @Unsigned long priv_flags;

    public char @Size(8) [] reset_methods;

    public @Unsigned short tph_cap;

    public char tph_mode;

    public char tph_req_type;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct pci_driver"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class pci_driver extends Struct {
    public String name;

    public Ptr<pci_device_id> id_table;

    public Ptr<?> probe;

    public Ptr<?> remove;

    public Ptr<?> suspend;

    public Ptr<?> resume;

    public Ptr<?> shutdown;

    public Ptr<?> sriov_configure;

    public Ptr<?> sriov_set_msix_vec_count;

    public Ptr<?> sriov_get_vf_total_msix;

    public Ptr<pci_error_handlers> err_handler;

    public Ptr<Ptr<attribute_group>> groups;

    public Ptr<Ptr<attribute_group>> dev_groups;

    public device_driver driver;

    public pci_dynids dynids;

    public boolean driver_managed_dma;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct pci_ops"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class pci_ops extends Struct {
    public Ptr<?> add_bus;

    public Ptr<?> remove_bus;

    public Ptr<?> map_bus;

    public Ptr<?> read;

    public Ptr<?> write;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct pci_dynids"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class pci_dynids extends Struct {
    public @OriginalName("spinlock_t") spinlock lock;

    public list_head list;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct pci_error_handlers"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class pci_error_handlers extends Struct {
    public Ptr<?> error_detected;

    public Ptr<?> mmio_enabled;

    public Ptr<?> slot_reset;

    public Ptr<?> reset_prepare;

    public Ptr<?> reset_done;

    public Ptr<?> resume;

    public Ptr<?> cor_error_detected;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct pci_msi_desc"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class pci_msi_desc extends Struct {
    @InlineUnion(5064)
    public @Unsigned int msi_mask;

    @InlineUnion(5064)
    public @Unsigned int msix_ctrl;

    public msi_attrib_of_pci_msi_desc msi_attrib;

    @InlineUnion(5066)
    public char mask_pos;

    @InlineUnion(5066)
    public Ptr<?> mask_base;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct pci_sysdata"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class pci_sysdata extends Struct {
    public int domain;

    public int node;

    public Ptr<acpi_device> companion;

    public Ptr<?> iommu;

    public Ptr<?> fwnode;

    public Ptr<pci_dev> vmd_dev;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct pci_extra_dev"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class pci_extra_dev extends Struct {
    public Ptr<pci_dev> @Size(4) [] dev;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct { u8 bus; u8 slot; u8 function; u8 channel; unsigned int reserved; }"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class pci_of_interface_path_of_edd_device_params extends Struct {
    public char bus;

    public char slot;

    public char function;

    public char channel;

    public @Unsigned int reserved;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct { union { short unsigned int rid; union hv_pci_bdf bdf; }; short unsigned int segment; union hv_pci_bus_range shadow_bus_range; short unsigned int phantom_function_bits; short unsigned int source_shadow; short unsigned int rsvdz0; short unsigned int device_type; }"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class pci_of_hv_device_id extends Struct {
    @InlineUnion(6820)
    public @Unsigned @OriginalName("hv_pci_rid") short rid;

    @InlineUnion(6820)
    public hv_pci_bdf bdf;

    public @Unsigned @OriginalName("hv_pci_segment") short segment;

    public hv_pci_bus_range shadow_bus_range;

    public @Unsigned short phantom_function_bits;

    public @Unsigned short source_shadow;

    public @Unsigned short rsvdz0;

    public @Unsigned short device_type;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct pci_mmcfg_region"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class pci_mmcfg_region extends Struct {
    public list_head list;

    public resource res;

    public @Unsigned long address;

    public String virt;

    public @Unsigned short segment;

    public char start_bus;

    public char end_bus;

    public char @Size(30) [] name;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct pci_hostbridge_probe"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class pci_hostbridge_probe extends Struct {
    public @Unsigned int bus;

    public @Unsigned int slot;

    public @Unsigned int vendor;

    public @Unsigned int device;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "enum pci_p2pdma_map_type"
  )
  public enum pci_p2pdma_map_type implements Enum<pci_p2pdma_map_type>, TypedEnum<pci_p2pdma_map_type, java.lang. @Unsigned Integer> {
    /**
     * {@code PCI_P2PDMA_MAP_UNKNOWN = 0}
     */
    @EnumMember(
        value = 0L,
        name = "PCI_P2PDMA_MAP_UNKNOWN"
    )
    PCI_P2PDMA_MAP_UNKNOWN,

    /**
     * {@code PCI_P2PDMA_MAP_NONE = 1}
     */
    @EnumMember(
        value = 1L,
        name = "PCI_P2PDMA_MAP_NONE"
    )
    PCI_P2PDMA_MAP_NONE,

    /**
     * {@code PCI_P2PDMA_MAP_NOT_SUPPORTED = 2}
     */
    @EnumMember(
        value = 2L,
        name = "PCI_P2PDMA_MAP_NOT_SUPPORTED"
    )
    PCI_P2PDMA_MAP_NOT_SUPPORTED,

    /**
     * {@code PCI_P2PDMA_MAP_BUS_ADDR = 3}
     */
    @EnumMember(
        value = 3L,
        name = "PCI_P2PDMA_MAP_BUS_ADDR"
    )
    PCI_P2PDMA_MAP_BUS_ADDR,

    /**
     * {@code PCI_P2PDMA_MAP_THRU_HOST_BRIDGE = 4}
     */
    @EnumMember(
        value = 4L,
        name = "PCI_P2PDMA_MAP_THRU_HOST_BRIDGE"
    )
    PCI_P2PDMA_MAP_THRU_HOST_BRIDGE
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct pci_p2pdma_map_state"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class pci_p2pdma_map_state extends Struct {
    public Ptr<dev_pagemap> pgmap;

    public pci_p2pdma_map_type map;

    public @Unsigned long bus_off;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "enum pci_channel_io"
  )
  public enum pci_channel_io implements Enum<pci_channel_io>, TypedEnum<pci_channel_io, java.lang. @Unsigned Integer> {
    /**
     * {@code pci_channel_io_normal = 1}
     */
    @EnumMember(
        value = 1L,
        name = "pci_channel_io_normal"
    )
    pci_channel_io_normal,

    /**
     * {@code pci_channel_io_frozen = 2}
     */
    @EnumMember(
        value = 2L,
        name = "pci_channel_io_frozen"
    )
    pci_channel_io_frozen,

    /**
     * {@code pci_channel_io_perm_failure = 3}
     */
    @EnumMember(
        value = 3L,
        name = "pci_channel_io_perm_failure"
    )
    pci_channel_io_perm_failure
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct pci_sriov"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class pci_sriov extends Struct {
    public int pos;

    public int nres;

    public @Unsigned int cap;

    public @Unsigned short ctrl;

    public @Unsigned short total_VFs;

    public @Unsigned short initial_VFs;

    public @Unsigned short num_VFs;

    public @Unsigned short offset;

    public @Unsigned short stride;

    public @Unsigned short vf_device;

    public @Unsigned int pgsz;

    public char link;

    public char max_VF_buses;

    public @Unsigned short driver_max_VFs;

    public Ptr<pci_dev> dev;

    public Ptr<pci_dev> self;

    public @Unsigned int _class;

    public char hdr_type;

    public @Unsigned short subsystem_vendor;

    public @Unsigned short subsystem_device;

    public @Unsigned @OriginalName("resource_size_t") long @Size(6) [] barsz;

    public @Unsigned short vf_rebar_cap;

    public boolean drivers_autoprobe;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct pci_bus_region"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class pci_bus_region extends Struct {
    public @Unsigned @OriginalName("pci_bus_addr_t") long start;

    public @Unsigned @OriginalName("pci_bus_addr_t") long end;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "enum pci_fixup_pass"
  )
  public enum pci_fixup_pass implements Enum<pci_fixup_pass>, TypedEnum<pci_fixup_pass, java.lang. @Unsigned Integer> {
    /**
     * {@code pci_fixup_early = 0}
     */
    @EnumMember(
        value = 0L,
        name = "pci_fixup_early"
    )
    pci_fixup_early,

    /**
     * {@code pci_fixup_header = 1}
     */
    @EnumMember(
        value = 1L,
        name = "pci_fixup_header"
    )
    pci_fixup_header,

    /**
     * {@code pci_fixup_final = 2}
     */
    @EnumMember(
        value = 2L,
        name = "pci_fixup_final"
    )
    pci_fixup_final,

    /**
     * {@code pci_fixup_enable = 3}
     */
    @EnumMember(
        value = 3L,
        name = "pci_fixup_enable"
    )
    pci_fixup_enable,

    /**
     * {@code pci_fixup_resume = 4}
     */
    @EnumMember(
        value = 4L,
        name = "pci_fixup_resume"
    )
    pci_fixup_resume,

    /**
     * {@code pci_fixup_suspend = 5}
     */
    @EnumMember(
        value = 5L,
        name = "pci_fixup_suspend"
    )
    pci_fixup_suspend,

    /**
     * {@code pci_fixup_resume_early = 6}
     */
    @EnumMember(
        value = 6L,
        name = "pci_fixup_resume_early"
    )
    pci_fixup_resume_early,

    /**
     * {@code pci_fixup_suspend_late = 7}
     */
    @EnumMember(
        value = 7L,
        name = "pci_fixup_suspend_late"
    )
    pci_fixup_suspend_late
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct pci_bus_resource"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class pci_bus_resource extends Struct {
    public list_head list;

    public Ptr<resource> res;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "enum pci_dev_flags"
  )
  public enum pci_dev_flags implements Enum<pci_dev_flags>, TypedEnum<pci_dev_flags, java.lang. @Unsigned Integer> {
    /**
     * {@code PCI_DEV_FLAGS_MSI_INTX_DISABLE_BUG = 1}
     */
    @EnumMember(
        value = 1L,
        name = "PCI_DEV_FLAGS_MSI_INTX_DISABLE_BUG"
    )
    PCI_DEV_FLAGS_MSI_INTX_DISABLE_BUG,

    /**
     * {@code PCI_DEV_FLAGS_NO_D3 = 2}
     */
    @EnumMember(
        value = 2L,
        name = "PCI_DEV_FLAGS_NO_D3"
    )
    PCI_DEV_FLAGS_NO_D3,

    /**
     * {@code PCI_DEV_FLAGS_ASSIGNED = 4}
     */
    @EnumMember(
        value = 4L,
        name = "PCI_DEV_FLAGS_ASSIGNED"
    )
    PCI_DEV_FLAGS_ASSIGNED,

    /**
     * {@code PCI_DEV_FLAGS_ACS_ENABLED_QUIRK = 8}
     */
    @EnumMember(
        value = 8L,
        name = "PCI_DEV_FLAGS_ACS_ENABLED_QUIRK"
    )
    PCI_DEV_FLAGS_ACS_ENABLED_QUIRK,

    /**
     * {@code PCI_DEV_FLAG_PCIE_BRIDGE_ALIAS = 32}
     */
    @EnumMember(
        value = 32L,
        name = "PCI_DEV_FLAG_PCIE_BRIDGE_ALIAS"
    )
    PCI_DEV_FLAG_PCIE_BRIDGE_ALIAS,

    /**
     * {@code PCI_DEV_FLAGS_NO_BUS_RESET = 64}
     */
    @EnumMember(
        value = 64L,
        name = "PCI_DEV_FLAGS_NO_BUS_RESET"
    )
    PCI_DEV_FLAGS_NO_BUS_RESET,

    /**
     * {@code PCI_DEV_FLAGS_NO_PM_RESET = 128}
     */
    @EnumMember(
        value = 128L,
        name = "PCI_DEV_FLAGS_NO_PM_RESET"
    )
    PCI_DEV_FLAGS_NO_PM_RESET,

    /**
     * {@code PCI_DEV_FLAGS_VPD_REF_F0 = 256}
     */
    @EnumMember(
        value = 256L,
        name = "PCI_DEV_FLAGS_VPD_REF_F0"
    )
    PCI_DEV_FLAGS_VPD_REF_F0,

    /**
     * {@code PCI_DEV_FLAGS_BRIDGE_XLATE_ROOT = 512}
     */
    @EnumMember(
        value = 512L,
        name = "PCI_DEV_FLAGS_BRIDGE_XLATE_ROOT"
    )
    PCI_DEV_FLAGS_BRIDGE_XLATE_ROOT,

    /**
     * {@code PCI_DEV_FLAGS_NO_FLR_RESET = 1024}
     */
    @EnumMember(
        value = 1024L,
        name = "PCI_DEV_FLAGS_NO_FLR_RESET"
    )
    PCI_DEV_FLAGS_NO_FLR_RESET,

    /**
     * {@code PCI_DEV_FLAGS_NO_RELAXED_ORDERING = 2048}
     */
    @EnumMember(
        value = 2048L,
        name = "PCI_DEV_FLAGS_NO_RELAXED_ORDERING"
    )
    PCI_DEV_FLAGS_NO_RELAXED_ORDERING,

    /**
     * {@code PCI_DEV_FLAGS_HAS_MSI_MASKING = 4096}
     */
    @EnumMember(
        value = 4096L,
        name = "PCI_DEV_FLAGS_HAS_MSI_MASKING"
    )
    PCI_DEV_FLAGS_HAS_MSI_MASKING,

    /**
     * {@code PCI_DEV_FLAGS_MSIX_TOUCH_ENTRY_DATA_FIRST = 8192}
     */
    @EnumMember(
        value = 8192L,
        name = "PCI_DEV_FLAGS_MSIX_TOUCH_ENTRY_DATA_FIRST"
    )
    PCI_DEV_FLAGS_MSIX_TOUCH_ENTRY_DATA_FIRST,

    /**
     * {@code PCI_DEV_FLAGS_NO_RRS_SV = 16384}
     */
    @EnumMember(
        value = 16384L,
        name = "PCI_DEV_FLAGS_NO_RRS_SV"
    )
    PCI_DEV_FLAGS_NO_RRS_SV
  }

  @Type(
      noCCodeGeneration = true,
      cType = "enum pci_bus_flags"
  )
  public enum pci_bus_flags implements Enum<pci_bus_flags>, TypedEnum<pci_bus_flags, java.lang. @Unsigned Integer> {
    /**
     * {@code PCI_BUS_FLAGS_NO_MSI = 1}
     */
    @EnumMember(
        value = 1L,
        name = "PCI_BUS_FLAGS_NO_MSI"
    )
    PCI_BUS_FLAGS_NO_MSI,

    /**
     * {@code PCI_BUS_FLAGS_NO_MMRBC = 2}
     */
    @EnumMember(
        value = 2L,
        name = "PCI_BUS_FLAGS_NO_MMRBC"
    )
    PCI_BUS_FLAGS_NO_MMRBC,

    /**
     * {@code PCI_BUS_FLAGS_NO_AERSID = 4}
     */
    @EnumMember(
        value = 4L,
        name = "PCI_BUS_FLAGS_NO_AERSID"
    )
    PCI_BUS_FLAGS_NO_AERSID,

    /**
     * {@code PCI_BUS_FLAGS_NO_EXTCFG = 8}
     */
    @EnumMember(
        value = 8L,
        name = "PCI_BUS_FLAGS_NO_EXTCFG"
    )
    PCI_BUS_FLAGS_NO_EXTCFG
  }

  @Type(
      noCCodeGeneration = true,
      cType = "enum pci_bus_speed"
  )
  public enum pci_bus_speed implements Enum<pci_bus_speed>, TypedEnum<pci_bus_speed, java.lang. @Unsigned Integer> {
    /**
     * {@code PCI_SPEED_33MHz = 0}
     */
    @EnumMember(
        value = 0L,
        name = "PCI_SPEED_33MHz"
    )
    PCI_SPEED_33MHz,

    /**
     * {@code PCI_SPEED_66MHz = 1}
     */
    @EnumMember(
        value = 1L,
        name = "PCI_SPEED_66MHz"
    )
    PCI_SPEED_66MHz,

    /**
     * {@code PCI_SPEED_66MHz_PCIX = 2}
     */
    @EnumMember(
        value = 2L,
        name = "PCI_SPEED_66MHz_PCIX"
    )
    PCI_SPEED_66MHz_PCIX,

    /**
     * {@code PCI_SPEED_100MHz_PCIX = 3}
     */
    @EnumMember(
        value = 3L,
        name = "PCI_SPEED_100MHz_PCIX"
    )
    PCI_SPEED_100MHz_PCIX,

    /**
     * {@code PCI_SPEED_133MHz_PCIX = 4}
     */
    @EnumMember(
        value = 4L,
        name = "PCI_SPEED_133MHz_PCIX"
    )
    PCI_SPEED_133MHz_PCIX,

    /**
     * {@code PCI_SPEED_66MHz_PCIX_ECC = 5}
     */
    @EnumMember(
        value = 5L,
        name = "PCI_SPEED_66MHz_PCIX_ECC"
    )
    PCI_SPEED_66MHz_PCIX_ECC,

    /**
     * {@code PCI_SPEED_100MHz_PCIX_ECC = 6}
     */
    @EnumMember(
        value = 6L,
        name = "PCI_SPEED_100MHz_PCIX_ECC"
    )
    PCI_SPEED_100MHz_PCIX_ECC,

    /**
     * {@code PCI_SPEED_133MHz_PCIX_ECC = 7}
     */
    @EnumMember(
        value = 7L,
        name = "PCI_SPEED_133MHz_PCIX_ECC"
    )
    PCI_SPEED_133MHz_PCIX_ECC,

    /**
     * {@code PCI_SPEED_66MHz_PCIX_266 = 9}
     */
    @EnumMember(
        value = 9L,
        name = "PCI_SPEED_66MHz_PCIX_266"
    )
    PCI_SPEED_66MHz_PCIX_266,

    /**
     * {@code PCI_SPEED_100MHz_PCIX_266 = 10}
     */
    @EnumMember(
        value = 10L,
        name = "PCI_SPEED_100MHz_PCIX_266"
    )
    PCI_SPEED_100MHz_PCIX_266,

    /**
     * {@code PCI_SPEED_133MHz_PCIX_266 = 11}
     */
    @EnumMember(
        value = 11L,
        name = "PCI_SPEED_133MHz_PCIX_266"
    )
    PCI_SPEED_133MHz_PCIX_266,

    /**
     * {@code AGP_UNKNOWN = 12}
     */
    @EnumMember(
        value = 12L,
        name = "AGP_UNKNOWN"
    )
    AGP_UNKNOWN,

    /**
     * {@code AGP_1X = 13}
     */
    @EnumMember(
        value = 13L,
        name = "AGP_1X"
    )
    AGP_1X,

    /**
     * {@code AGP_2X = 14}
     */
    @EnumMember(
        value = 14L,
        name = "AGP_2X"
    )
    AGP_2X,

    /**
     * {@code AGP_4X = 15}
     */
    @EnumMember(
        value = 15L,
        name = "AGP_4X"
    )
    AGP_4X,

    /**
     * {@code AGP_8X = 16}
     */
    @EnumMember(
        value = 16L,
        name = "AGP_8X"
    )
    AGP_8X,

    /**
     * {@code PCI_SPEED_66MHz_PCIX_533 = 17}
     */
    @EnumMember(
        value = 17L,
        name = "PCI_SPEED_66MHz_PCIX_533"
    )
    PCI_SPEED_66MHz_PCIX_533,

    /**
     * {@code PCI_SPEED_100MHz_PCIX_533 = 18}
     */
    @EnumMember(
        value = 18L,
        name = "PCI_SPEED_100MHz_PCIX_533"
    )
    PCI_SPEED_100MHz_PCIX_533,

    /**
     * {@code PCI_SPEED_133MHz_PCIX_533 = 19}
     */
    @EnumMember(
        value = 19L,
        name = "PCI_SPEED_133MHz_PCIX_533"
    )
    PCI_SPEED_133MHz_PCIX_533,

    /**
     * {@code PCIE_SPEED_2_5GT = 20}
     */
    @EnumMember(
        value = 20L,
        name = "PCIE_SPEED_2_5GT"
    )
    PCIE_SPEED_2_5GT,

    /**
     * {@code PCIE_SPEED_5_0GT = 21}
     */
    @EnumMember(
        value = 21L,
        name = "PCIE_SPEED_5_0GT"
    )
    PCIE_SPEED_5_0GT,

    /**
     * {@code PCIE_SPEED_8_0GT = 22}
     */
    @EnumMember(
        value = 22L,
        name = "PCIE_SPEED_8_0GT"
    )
    PCIE_SPEED_8_0GT,

    /**
     * {@code PCIE_SPEED_16_0GT = 23}
     */
    @EnumMember(
        value = 23L,
        name = "PCIE_SPEED_16_0GT"
    )
    PCIE_SPEED_16_0GT,

    /**
     * {@code PCIE_SPEED_32_0GT = 24}
     */
    @EnumMember(
        value = 24L,
        name = "PCIE_SPEED_32_0GT"
    )
    PCIE_SPEED_32_0GT,

    /**
     * {@code PCIE_SPEED_64_0GT = 25}
     */
    @EnumMember(
        value = 25L,
        name = "PCIE_SPEED_64_0GT"
    )
    PCIE_SPEED_64_0GT,

    /**
     * {@code PCI_SPEED_UNKNOWN = 255}
     */
    @EnumMember(
        value = 255L,
        name = "PCI_SPEED_UNKNOWN"
    )
    PCI_SPEED_UNKNOWN
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct pci_host_bridge"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class pci_host_bridge extends Struct {
    public device dev;

    public Ptr<pci_bus> bus;

    public Ptr<pci_ops> ops;

    public Ptr<pci_ops> child_ops;

    public Ptr<?> sysdata;

    public int busnr;

    public int domain_nr;

    public list_head windows;

    public list_head dma_ranges;

    public Ptr<?> swizzle_irq;

    public Ptr<?> map_irq;

    public Ptr<?> release_fn;

    public Ptr<?> enable_device;

    public Ptr<?> disable_device;

    public Ptr<?> release_data;

    public @Unsigned int ignore_reset_delay;

    public @Unsigned int no_ext_tags;

    public @Unsigned int no_inc_mrrs;

    public @Unsigned int native_aer;

    public @Unsigned int native_pcie_hotplug;

    public @Unsigned int native_shpc_hotplug;

    public @Unsigned int native_pme;

    public @Unsigned int native_ltr;

    public @Unsigned int native_dpc;

    public @Unsigned int native_cxl_error;

    public @Unsigned int preserve_config;

    public @Unsigned int size_windows;

    public @Unsigned int msi_domain;

    public Ptr<?> align_resource;

    public @Unsigned long @Size(0) [] _private;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "enum pci_bar_type"
  )
  public enum pci_bar_type implements Enum<pci_bar_type>, TypedEnum<pci_bar_type, java.lang. @Unsigned Integer> {
    /**
     * {@code pci_bar_unknown = 0}
     */
    @EnumMember(
        value = 0L,
        name = "pci_bar_unknown"
    )
    pci_bar_unknown,

    /**
     * {@code pci_bar_io = 1}
     */
    @EnumMember(
        value = 1L,
        name = "pci_bar_io"
    )
    pci_bar_io,

    /**
     * {@code pci_bar_mem32 = 2}
     */
    @EnumMember(
        value = 2L,
        name = "pci_bar_mem32"
    )
    pci_bar_mem32,

    /**
     * {@code pci_bar_mem64 = 3}
     */
    @EnumMember(
        value = 3L,
        name = "pci_bar_mem64"
    )
    pci_bar_mem64
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct pci_domain_busn_res"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class pci_domain_busn_res extends Struct {
    public list_head list;

    public resource res;

    public int domain_nr;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct pci_cap_saved_data"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class pci_cap_saved_data extends Struct {
    public @Unsigned short cap_nr;

    public boolean cap_extended;

    public @Unsigned int size;

    public @Unsigned int @Size(0) [] data;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct pci_cap_saved_state"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class pci_cap_saved_state extends Struct {
    public hlist_node next;

    public pci_cap_saved_data cap;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct pci_reset_fn_method"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class pci_reset_fn_method extends Struct {
    public Ptr<?> reset_fn;

    public String name;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct pci_pme_device"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class pci_pme_device extends Struct {
    public list_head list;

    public Ptr<pci_dev> dev;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct pci_acs"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class pci_acs extends Struct {
    public @Unsigned short cap;

    public @Unsigned short ctrl;

    public @Unsigned short fw_ctrl;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct pci_saved_state"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class pci_saved_state extends Struct {
    public @Unsigned int @Size(16) [] config_space;

    public pci_cap_saved_data @Size(0) [] cap;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "enum pci_ers_result"
  )
  public enum pci_ers_result implements Enum<pci_ers_result>, TypedEnum<pci_ers_result, java.lang. @Unsigned Integer> {
    /**
     * {@code PCI_ERS_RESULT_NONE = 1}
     */
    @EnumMember(
        value = 1L,
        name = "PCI_ERS_RESULT_NONE"
    )
    PCI_ERS_RESULT_NONE,

    /**
     * {@code PCI_ERS_RESULT_CAN_RECOVER = 2}
     */
    @EnumMember(
        value = 2L,
        name = "PCI_ERS_RESULT_CAN_RECOVER"
    )
    PCI_ERS_RESULT_CAN_RECOVER,

    /**
     * {@code PCI_ERS_RESULT_NEED_RESET = 3}
     */
    @EnumMember(
        value = 3L,
        name = "PCI_ERS_RESULT_NEED_RESET"
    )
    PCI_ERS_RESULT_NEED_RESET,

    /**
     * {@code PCI_ERS_RESULT_DISCONNECT = 4}
     */
    @EnumMember(
        value = 4L,
        name = "PCI_ERS_RESULT_DISCONNECT"
    )
    PCI_ERS_RESULT_DISCONNECT,

    /**
     * {@code PCI_ERS_RESULT_RECOVERED = 5}
     */
    @EnumMember(
        value = 5L,
        name = "PCI_ERS_RESULT_RECOVERED"
    )
    PCI_ERS_RESULT_RECOVERED,

    /**
     * {@code PCI_ERS_RESULT_NO_AER_DRIVER = 6}
     */
    @EnumMember(
        value = 6L,
        name = "PCI_ERS_RESULT_NO_AER_DRIVER"
    )
    PCI_ERS_RESULT_NO_AER_DRIVER
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct pci_dynid"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class pci_dynid extends Struct {
    public list_head node;

    public pci_device_id id;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct pci_dev_resource"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class pci_dev_resource extends Struct {
    public list_head list;

    public Ptr<resource> res;

    public Ptr<pci_dev> dev;

    public @Unsigned @OriginalName("resource_size_t") long start;

    public @Unsigned @OriginalName("resource_size_t") long end;

    public @Unsigned @OriginalName("resource_size_t") long add_size;

    public @Unsigned @OriginalName("resource_size_t") long min_align;

    public @Unsigned long flags;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "enum pci_mmap_state"
  )
  public enum pci_mmap_state implements Enum<pci_mmap_state>, TypedEnum<pci_mmap_state, java.lang. @Unsigned Integer> {
    /**
     * {@code pci_mmap_io = 0}
     */
    @EnumMember(
        value = 0L,
        name = "pci_mmap_io"
    )
    pci_mmap_io,

    /**
     * {@code pci_mmap_mem = 1}
     */
    @EnumMember(
        value = 1L,
        name = "pci_mmap_mem"
    )
    pci_mmap_mem
  }

  @Type(
      noCCodeGeneration = true,
      cType = "enum pci_mmap_api"
  )
  public enum pci_mmap_api implements Enum<pci_mmap_api>, TypedEnum<pci_mmap_api, java.lang. @Unsigned Integer> {
    /**
     * {@code PCI_MMAP_SYSFS = 0}
     */
    @EnumMember(
        value = 0L,
        name = "PCI_MMAP_SYSFS"
    )
    PCI_MMAP_SYSFS,

    /**
     * {@code PCI_MMAP_PROCFS = 1}
     */
    @EnumMember(
        value = 1L,
        name = "PCI_MMAP_PROCFS"
    )
    PCI_MMAP_PROCFS
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct pci_ptm_debugfs"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class pci_ptm_debugfs extends Struct {
    public Ptr<dentry> debugfs;

    public Ptr<pcie_ptm_ops> ops;

    public mutex lock;

    public Ptr<?> pdata;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct pci_filp_private"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class pci_filp_private extends Struct {
    public pci_mmap_state mmap_state;

    public int write_combine;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct pci_slot_attribute"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class pci_slot_attribute extends Struct {
    public attribute attr;

    public Ptr<?> show;

    public Ptr<?> store;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "enum pci_irq_reroute_variant"
  )
  public enum pci_irq_reroute_variant implements Enum<pci_irq_reroute_variant>, TypedEnum<pci_irq_reroute_variant, java.lang. @Unsigned Integer> {
    /**
     * {@code INTEL_IRQ_REROUTE_VARIANT = 1}
     */
    @EnumMember(
        value = 1L,
        name = "INTEL_IRQ_REROUTE_VARIANT"
    )
    INTEL_IRQ_REROUTE_VARIANT,

    /**
     * {@code MAX_IRQ_REROUTE_VARIANTS = 3}
     */
    @EnumMember(
        value = 3L,
        name = "MAX_IRQ_REROUTE_VARIANTS"
    )
    MAX_IRQ_REROUTE_VARIANTS
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct pci_fixup"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class pci_fixup extends Struct {
    public @Unsigned short vendor;

    public @Unsigned short device;

    public @Unsigned int _class;

    public @Unsigned int class_shift;

    public int hook_offset;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct pci_dev_reset_methods"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class pci_dev_reset_methods extends Struct {
    public @Unsigned short vendor;

    public @Unsigned short device;

    public Ptr<?> reset;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct pci_dev_acs_enabled"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class pci_dev_acs_enabled extends Struct {
    public @Unsigned short vendor;

    public @Unsigned short device;

    public Ptr<?> acs_enabled;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct pci_dev_acs_ops"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class pci_dev_acs_ops extends Struct {
    public @Unsigned short vendor;

    public @Unsigned short device;

    public Ptr<?> enable_acs;

    public Ptr<?> disable_acs_redir;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct pci_p2pdma"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class pci_p2pdma extends Struct {
    public Ptr<gen_pool> pool;

    public boolean p2pmem_published;

    public xarray map_types;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct pci_p2pdma_pagemap"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class pci_p2pdma_pagemap extends Struct {
    public Ptr<pci_dev> provider;

    public @Unsigned long bus_offset;

    public dev_pagemap pgmap;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct pci_p2pdma_whitelist_entry"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class pci_p2pdma_whitelist_entry extends Struct {
    public @Unsigned short vendor;

    public @Unsigned short device;

    public flags_of_pci_p2pdma_whitelist_entry flags;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct pci_doe_mb"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class pci_doe_mb extends Struct {
    public Ptr<pci_dev> pdev;

    public @Unsigned short cap_offset;

    public xarray feats;

    public @OriginalName("wait_queue_head_t") wait_queue_head wq;

    public Ptr<workqueue_struct> work_queue;

    public @Unsigned long flags;

    public Ptr<device_attribute> sysfs_attrs;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct pci_doe_feature"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class pci_doe_feature extends Struct {
    public @Unsigned short vid;

    public char type;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct pci_doe_task"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class pci_doe_task extends Struct {
    public pci_doe_feature feat;

    public Ptr<java.lang. @Unsigned @OriginalName("__le32") Integer> request_pl;

    public @Unsigned long request_pl_sz;

    public Ptr<java.lang. @Unsigned @OriginalName("__le32") Integer> response_pl;

    public @Unsigned long response_pl_sz;

    public int rv;

    public Ptr<?> complete;

    public Ptr<?> _private;

    public work_struct work;

    public Ptr<pci_doe_mb> doe_mb;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct pci_epf_device_id"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class pci_epf_device_id extends Struct {
    public char @Size(20) [] name;

    public @Unsigned @OriginalName("kernel_ulong_t") long driver_data;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "enum pci_interrupt_pin"
  )
  public enum pci_interrupt_pin implements Enum<pci_interrupt_pin>, TypedEnum<pci_interrupt_pin, java.lang. @Unsigned Integer> {
    /**
     * {@code PCI_INTERRUPT_UNKNOWN = 0}
     */
    @EnumMember(
        value = 0L,
        name = "PCI_INTERRUPT_UNKNOWN"
    )
    PCI_INTERRUPT_UNKNOWN,

    /**
     * {@code PCI_INTERRUPT_INTA = 1}
     */
    @EnumMember(
        value = 1L,
        name = "PCI_INTERRUPT_INTA"
    )
    PCI_INTERRUPT_INTA,

    /**
     * {@code PCI_INTERRUPT_INTB = 2}
     */
    @EnumMember(
        value = 2L,
        name = "PCI_INTERRUPT_INTB"
    )
    PCI_INTERRUPT_INTB,

    /**
     * {@code PCI_INTERRUPT_INTC = 3}
     */
    @EnumMember(
        value = 3L,
        name = "PCI_INTERRUPT_INTC"
    )
    PCI_INTERRUPT_INTC,

    /**
     * {@code PCI_INTERRUPT_INTD = 4}
     */
    @EnumMember(
        value = 4L,
        name = "PCI_INTERRUPT_INTD"
    )
    PCI_INTERRUPT_INTD
  }

  @Type(
      noCCodeGeneration = true,
      cType = "enum pci_barno"
  )
  public enum pci_barno implements Enum<pci_barno>, TypedEnum<pci_barno, java.lang.Integer> {
    /**
     * {@code NO_BAR = -1}
     */
    @EnumMember(
        value = -1L,
        name = "NO_BAR"
    )
    NO_BAR,

    /**
     * {@code BAR_0 = 0}
     */
    @EnumMember(
        value = 0L,
        name = "BAR_0"
    )
    BAR_0,

    /**
     * {@code BAR_1 = 1}
     */
    @EnumMember(
        value = 1L,
        name = "BAR_1"
    )
    BAR_1,

    /**
     * {@code BAR_2 = 2}
     */
    @EnumMember(
        value = 2L,
        name = "BAR_2"
    )
    BAR_2,

    /**
     * {@code BAR_3 = 3}
     */
    @EnumMember(
        value = 3L,
        name = "BAR_3"
    )
    BAR_3,

    /**
     * {@code BAR_4 = 4}
     */
    @EnumMember(
        value = 4L,
        name = "BAR_4"
    )
    BAR_4,

    /**
     * {@code BAR_5 = 5}
     */
    @EnumMember(
        value = 5L,
        name = "BAR_5"
    )
    BAR_5
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct pci_epf_header"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class pci_epf_header extends Struct {
    public @Unsigned short vendorid;

    public @Unsigned short deviceid;

    public char revid;

    public char progif_code;

    public char subclass_code;

    public char baseclass_code;

    public char cache_line_size;

    public @Unsigned short subsys_vendor_id;

    public @Unsigned short subsys_id;

    public pci_interrupt_pin interrupt_pin;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct pci_epf_ops"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class pci_epf_ops extends Struct {
    public Ptr<?> bind;

    public Ptr<?> unbind;

    public Ptr<?> add_cfs;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct pci_epf"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class pci_epf extends Struct {
    public device dev;

    public String name;

    public Ptr<pci_epf_header> header;

    public pci_epf_bar @Size(6) [] bar;

    public char msi_interrupts;

    public @Unsigned short msix_interrupts;

    public char func_no;

    public char vfunc_no;

    public Ptr<pci_epc> epc;

    public Ptr<pci_epf> epf_pf;

    public Ptr<pci_epf_driver> driver;

    public Ptr<pci_epf_device_id> id;

    public list_head list;

    public mutex lock;

    public Ptr<pci_epc> sec_epc;

    public list_head sec_epc_list;

    public pci_epf_bar @Size(6) [] sec_epc_bar;

    public char sec_epc_func_no;

    public Ptr<config_group> group;

    public @Unsigned int is_bound;

    public @Unsigned int is_vf;

    public @Unsigned long vfunction_num_map;

    public list_head pci_vepf;

    public Ptr<pci_epc_event_ops> event_ops;

    public Ptr<pci_epf_doorbell_msg> db_msg;

    public @Unsigned short num_db;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct pci_epc_event_ops"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class pci_epc_event_ops extends Struct {
    public Ptr<?> epc_init;

    public Ptr<?> epc_deinit;

    public Ptr<?> link_up;

    public Ptr<?> link_down;

    public Ptr<?> bus_master_enable;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct pci_epf_driver"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class pci_epf_driver extends Struct {
    public Ptr<?> probe;

    public Ptr<?> remove;

    public device_driver driver;

    public Ptr<pci_epf_ops> ops;

    public Ptr<module> owner;

    public list_head epf_group;

    public Ptr<pci_epf_device_id> id_table;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct pci_epf_bar"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class pci_epf_bar extends Struct {
    public @Unsigned @OriginalName("dma_addr_t") long phys_addr;

    public Ptr<?> addr;

    public @Unsigned long size;

    public @Unsigned long aligned_size;

    public pci_barno barno;

    public int flags;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct pci_epf_doorbell_msg"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class pci_epf_doorbell_msg extends Struct {
    public msi_msg msg;

    public int virq;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct pci_epc"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class pci_epc extends Struct {
    public device dev;

    public list_head pci_epf;

    public mutex list_lock;

    public Ptr<pci_epc_ops> ops;

    public Ptr<Ptr<pci_epc_mem>> windows;

    public Ptr<pci_epc_mem> mem;

    public @Unsigned int num_windows;

    public char max_functions;

    public Ptr<java.lang.Character> max_vfs;

    public Ptr<config_group> group;

    public mutex lock;

    public @Unsigned long function_num_map;

    public int domain_nr;

    public boolean init_complete;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "enum pci_epc_interface_type"
  )
  public enum pci_epc_interface_type implements Enum<pci_epc_interface_type>, TypedEnum<pci_epc_interface_type, java.lang.Integer> {
    /**
     * {@code UNKNOWN_INTERFACE = -1}
     */
    @EnumMember(
        value = -1L,
        name = "UNKNOWN_INTERFACE"
    )
    UNKNOWN_INTERFACE,

    /**
     * {@code PRIMARY_INTERFACE = 0}
     */
    @EnumMember(
        value = 0L,
        name = "PRIMARY_INTERFACE"
    )
    PRIMARY_INTERFACE,

    /**
     * {@code SECONDARY_INTERFACE = 1}
     */
    @EnumMember(
        value = 1L,
        name = "SECONDARY_INTERFACE"
    )
    SECONDARY_INTERFACE
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct pci_epc_ops"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class pci_epc_ops extends Struct {
    public Ptr<?> write_header;

    public Ptr<?> set_bar;

    public Ptr<?> clear_bar;

    public Ptr<?> align_addr;

    public Ptr<?> map_addr;

    public Ptr<?> unmap_addr;

    public Ptr<?> set_msi;

    public Ptr<?> get_msi;

    public Ptr<?> set_msix;

    public Ptr<?> get_msix;

    public Ptr<?> raise_irq;

    public Ptr<?> map_msi_irq;

    public Ptr<?> start;

    public Ptr<?> stop;

    public Ptr<?> get_features;

    public Ptr<module> owner;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct pci_epc_features"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class pci_epc_features extends Struct {
    public @Unsigned int linkup_notifier;

    public @Unsigned int msi_capable;

    public @Unsigned int msix_capable;

    public @Unsigned int intx_capable;

    public pci_epc_bar_desc @Size(6) [] bar;

    public @Unsigned long align;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct pci_epc_mem_window"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class pci_epc_mem_window extends Struct {
    public @Unsigned @OriginalName("phys_addr_t") long phys_base;

    public @Unsigned long size;

    public @Unsigned long page_size;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct pci_epc_mem"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class pci_epc_mem extends Struct {
    public pci_epc_mem_window window;

    public Ptr<java.lang. @Unsigned Long> bitmap;

    public int pages;

    public mutex lock;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "enum pci_epc_bar_type"
  )
  public enum pci_epc_bar_type implements Enum<pci_epc_bar_type>, TypedEnum<pci_epc_bar_type, java.lang. @Unsigned Integer> {
    /**
     * {@code BAR_PROGRAMMABLE = 0}
     */
    @EnumMember(
        value = 0L,
        name = "BAR_PROGRAMMABLE"
    )
    BAR_PROGRAMMABLE,

    /**
     * {@code BAR_FIXED = 1}
     */
    @EnumMember(
        value = 1L,
        name = "BAR_FIXED"
    )
    BAR_FIXED,

    /**
     * {@code BAR_RESIZABLE = 2}
     */
    @EnumMember(
        value = 2L,
        name = "BAR_RESIZABLE"
    )
    BAR_RESIZABLE,

    /**
     * {@code BAR_RESERVED = 3}
     */
    @EnumMember(
        value = 3L,
        name = "BAR_RESERVED"
    )
    BAR_RESERVED
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct pci_epc_bar_desc"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class pci_epc_bar_desc extends Struct {
    public pci_epc_bar_type type;

    public @Unsigned long fixed_size;

    public boolean only_64bit;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct pci_epf_group"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class pci_epf_group extends Struct {
    public config_group group;

    public config_group primary_epc_group;

    public config_group secondary_epc_group;

    public delayed_work cfs_work;

    public Ptr<pci_epf> epf;

    public int index;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct pci_epc_group"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class pci_epc_group extends Struct {
    public config_group group;

    public Ptr<pci_epc> epc;

    public boolean start;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct pci_epc_map"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class pci_epc_map extends Struct {
    public @Unsigned long pci_addr;

    public @Unsigned long pci_size;

    public @Unsigned long map_pci_addr;

    public @Unsigned long map_size;

    public @Unsigned @OriginalName("phys_addr_t") long phys_base;

    public @Unsigned @OriginalName("phys_addr_t") long phys_addr;

    public Ptr<?> virt_base;

    public Ptr<?> virt_addr;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct pci_eq_presets"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class pci_eq_presets extends Struct {
    public @Unsigned short @Size(16) [] eq_presets_8gts;

    public char @Size(48) [] eq_presets_Ngts;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct pci_epf_msix_tbl"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class pci_epf_msix_tbl extends Struct {
    public @Unsigned long msg_addr;

    public @Unsigned int msg_data;

    public @Unsigned int vector_ctrl;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct pci_osc_bit_struct"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class pci_osc_bit_struct extends Struct {
    public @Unsigned int bit;

    public String desc;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct { unsigned int offset; unsigned int reserved; }"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class pci_common_cfg_of_selector_of_virtio_dev_part_hdr extends Struct {
    public @Unsigned @OriginalName("__le32") int offset;

    public @Unsigned @OriginalName("__le32") int reserved;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct pci_device_reset"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class pci_device_reset extends Struct {
    public physdev_pci_device dev;

    public @Unsigned @OriginalName("uint32_t") int flags;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct pci_serial_quirk"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class pci_serial_quirk extends Struct {
    public @Unsigned int vendor;

    public @Unsigned int device;

    public @Unsigned int subvendor;

    public @Unsigned int subdevice;

    public Ptr<?> probe;

    public Ptr<?> init;

    public Ptr<?> setup;

    public Ptr<?> exit;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "enum pci_board_num_t"
  )
  public enum pci_board_num_t implements Enum<pci_board_num_t>, TypedEnum<pci_board_num_t, java.lang. @Unsigned Integer> {
    /**
     * {@code pbn_default = 0}
     */
    @EnumMember(
        value = 0L,
        name = "pbn_default"
    )
    pbn_default,

    /**
     * {@code pbn_b0_1_115200 = 1}
     */
    @EnumMember(
        value = 1L,
        name = "pbn_b0_1_115200"
    )
    pbn_b0_1_115200,

    /**
     * {@code pbn_b0_2_115200 = 2}
     */
    @EnumMember(
        value = 2L,
        name = "pbn_b0_2_115200"
    )
    pbn_b0_2_115200,

    /**
     * {@code pbn_b0_4_115200 = 3}
     */
    @EnumMember(
        value = 3L,
        name = "pbn_b0_4_115200"
    )
    pbn_b0_4_115200,

    /**
     * {@code pbn_b0_5_115200 = 4}
     */
    @EnumMember(
        value = 4L,
        name = "pbn_b0_5_115200"
    )
    pbn_b0_5_115200,

    /**
     * {@code pbn_b0_8_115200 = 5}
     */
    @EnumMember(
        value = 5L,
        name = "pbn_b0_8_115200"
    )
    pbn_b0_8_115200,

    /**
     * {@code pbn_b0_1_921600 = 6}
     */
    @EnumMember(
        value = 6L,
        name = "pbn_b0_1_921600"
    )
    pbn_b0_1_921600,

    /**
     * {@code pbn_b0_2_921600 = 7}
     */
    @EnumMember(
        value = 7L,
        name = "pbn_b0_2_921600"
    )
    pbn_b0_2_921600,

    /**
     * {@code pbn_b0_4_921600 = 8}
     */
    @EnumMember(
        value = 8L,
        name = "pbn_b0_4_921600"
    )
    pbn_b0_4_921600,

    /**
     * {@code pbn_b0_2_1130000 = 9}
     */
    @EnumMember(
        value = 9L,
        name = "pbn_b0_2_1130000"
    )
    pbn_b0_2_1130000,

    /**
     * {@code pbn_b0_4_1152000 = 10}
     */
    @EnumMember(
        value = 10L,
        name = "pbn_b0_4_1152000"
    )
    pbn_b0_4_1152000,

    /**
     * {@code pbn_b0_4_1250000 = 11}
     */
    @EnumMember(
        value = 11L,
        name = "pbn_b0_4_1250000"
    )
    pbn_b0_4_1250000,

    /**
     * {@code pbn_b0_2_1843200 = 12}
     */
    @EnumMember(
        value = 12L,
        name = "pbn_b0_2_1843200"
    )
    pbn_b0_2_1843200,

    /**
     * {@code pbn_b0_4_1843200 = 13}
     */
    @EnumMember(
        value = 13L,
        name = "pbn_b0_4_1843200"
    )
    pbn_b0_4_1843200,

    /**
     * {@code pbn_b0_1_15625000 = 14}
     */
    @EnumMember(
        value = 14L,
        name = "pbn_b0_1_15625000"
    )
    pbn_b0_1_15625000,

    /**
     * {@code pbn_b0_bt_1_115200 = 15}
     */
    @EnumMember(
        value = 15L,
        name = "pbn_b0_bt_1_115200"
    )
    pbn_b0_bt_1_115200,

    /**
     * {@code pbn_b0_bt_2_115200 = 16}
     */
    @EnumMember(
        value = 16L,
        name = "pbn_b0_bt_2_115200"
    )
    pbn_b0_bt_2_115200,

    /**
     * {@code pbn_b0_bt_4_115200 = 17}
     */
    @EnumMember(
        value = 17L,
        name = "pbn_b0_bt_4_115200"
    )
    pbn_b0_bt_4_115200,

    /**
     * {@code pbn_b0_bt_8_115200 = 18}
     */
    @EnumMember(
        value = 18L,
        name = "pbn_b0_bt_8_115200"
    )
    pbn_b0_bt_8_115200,

    /**
     * {@code pbn_b0_bt_1_460800 = 19}
     */
    @EnumMember(
        value = 19L,
        name = "pbn_b0_bt_1_460800"
    )
    pbn_b0_bt_1_460800,

    /**
     * {@code pbn_b0_bt_2_460800 = 20}
     */
    @EnumMember(
        value = 20L,
        name = "pbn_b0_bt_2_460800"
    )
    pbn_b0_bt_2_460800,

    /**
     * {@code pbn_b0_bt_4_460800 = 21}
     */
    @EnumMember(
        value = 21L,
        name = "pbn_b0_bt_4_460800"
    )
    pbn_b0_bt_4_460800,

    /**
     * {@code pbn_b0_bt_1_921600 = 22}
     */
    @EnumMember(
        value = 22L,
        name = "pbn_b0_bt_1_921600"
    )
    pbn_b0_bt_1_921600,

    /**
     * {@code pbn_b0_bt_2_921600 = 23}
     */
    @EnumMember(
        value = 23L,
        name = "pbn_b0_bt_2_921600"
    )
    pbn_b0_bt_2_921600,

    /**
     * {@code pbn_b0_bt_4_921600 = 24}
     */
    @EnumMember(
        value = 24L,
        name = "pbn_b0_bt_4_921600"
    )
    pbn_b0_bt_4_921600,

    /**
     * {@code pbn_b0_bt_8_921600 = 25}
     */
    @EnumMember(
        value = 25L,
        name = "pbn_b0_bt_8_921600"
    )
    pbn_b0_bt_8_921600,

    /**
     * {@code pbn_b1_1_115200 = 26}
     */
    @EnumMember(
        value = 26L,
        name = "pbn_b1_1_115200"
    )
    pbn_b1_1_115200,

    /**
     * {@code pbn_b1_2_115200 = 27}
     */
    @EnumMember(
        value = 27L,
        name = "pbn_b1_2_115200"
    )
    pbn_b1_2_115200,

    /**
     * {@code pbn_b1_4_115200 = 28}
     */
    @EnumMember(
        value = 28L,
        name = "pbn_b1_4_115200"
    )
    pbn_b1_4_115200,

    /**
     * {@code pbn_b1_8_115200 = 29}
     */
    @EnumMember(
        value = 29L,
        name = "pbn_b1_8_115200"
    )
    pbn_b1_8_115200,

    /**
     * {@code pbn_b1_16_115200 = 30}
     */
    @EnumMember(
        value = 30L,
        name = "pbn_b1_16_115200"
    )
    pbn_b1_16_115200,

    /**
     * {@code pbn_b1_1_921600 = 31}
     */
    @EnumMember(
        value = 31L,
        name = "pbn_b1_1_921600"
    )
    pbn_b1_1_921600,

    /**
     * {@code pbn_b1_2_921600 = 32}
     */
    @EnumMember(
        value = 32L,
        name = "pbn_b1_2_921600"
    )
    pbn_b1_2_921600,

    /**
     * {@code pbn_b1_4_921600 = 33}
     */
    @EnumMember(
        value = 33L,
        name = "pbn_b1_4_921600"
    )
    pbn_b1_4_921600,

    /**
     * {@code pbn_b1_8_921600 = 34}
     */
    @EnumMember(
        value = 34L,
        name = "pbn_b1_8_921600"
    )
    pbn_b1_8_921600,

    /**
     * {@code pbn_b1_2_1250000 = 35}
     */
    @EnumMember(
        value = 35L,
        name = "pbn_b1_2_1250000"
    )
    pbn_b1_2_1250000,

    /**
     * {@code pbn_b1_bt_1_115200 = 36}
     */
    @EnumMember(
        value = 36L,
        name = "pbn_b1_bt_1_115200"
    )
    pbn_b1_bt_1_115200,

    /**
     * {@code pbn_b1_bt_2_115200 = 37}
     */
    @EnumMember(
        value = 37L,
        name = "pbn_b1_bt_2_115200"
    )
    pbn_b1_bt_2_115200,

    /**
     * {@code pbn_b1_bt_4_115200 = 38}
     */
    @EnumMember(
        value = 38L,
        name = "pbn_b1_bt_4_115200"
    )
    pbn_b1_bt_4_115200,

    /**
     * {@code pbn_b1_bt_2_921600 = 39}
     */
    @EnumMember(
        value = 39L,
        name = "pbn_b1_bt_2_921600"
    )
    pbn_b1_bt_2_921600,

    /**
     * {@code pbn_b1_1_1382400 = 40}
     */
    @EnumMember(
        value = 40L,
        name = "pbn_b1_1_1382400"
    )
    pbn_b1_1_1382400,

    /**
     * {@code pbn_b1_2_1382400 = 41}
     */
    @EnumMember(
        value = 41L,
        name = "pbn_b1_2_1382400"
    )
    pbn_b1_2_1382400,

    /**
     * {@code pbn_b1_4_1382400 = 42}
     */
    @EnumMember(
        value = 42L,
        name = "pbn_b1_4_1382400"
    )
    pbn_b1_4_1382400,

    /**
     * {@code pbn_b1_8_1382400 = 43}
     */
    @EnumMember(
        value = 43L,
        name = "pbn_b1_8_1382400"
    )
    pbn_b1_8_1382400,

    /**
     * {@code pbn_b2_1_115200 = 44}
     */
    @EnumMember(
        value = 44L,
        name = "pbn_b2_1_115200"
    )
    pbn_b2_1_115200,

    /**
     * {@code pbn_b2_2_115200 = 45}
     */
    @EnumMember(
        value = 45L,
        name = "pbn_b2_2_115200"
    )
    pbn_b2_2_115200,

    /**
     * {@code pbn_b2_4_115200 = 46}
     */
    @EnumMember(
        value = 46L,
        name = "pbn_b2_4_115200"
    )
    pbn_b2_4_115200,

    /**
     * {@code pbn_b2_8_115200 = 47}
     */
    @EnumMember(
        value = 47L,
        name = "pbn_b2_8_115200"
    )
    pbn_b2_8_115200,

    /**
     * {@code pbn_b2_1_460800 = 48}
     */
    @EnumMember(
        value = 48L,
        name = "pbn_b2_1_460800"
    )
    pbn_b2_1_460800,

    /**
     * {@code pbn_b2_4_460800 = 49}
     */
    @EnumMember(
        value = 49L,
        name = "pbn_b2_4_460800"
    )
    pbn_b2_4_460800,

    /**
     * {@code pbn_b2_8_460800 = 50}
     */
    @EnumMember(
        value = 50L,
        name = "pbn_b2_8_460800"
    )
    pbn_b2_8_460800,

    /**
     * {@code pbn_b2_16_460800 = 51}
     */
    @EnumMember(
        value = 51L,
        name = "pbn_b2_16_460800"
    )
    pbn_b2_16_460800,

    /**
     * {@code pbn_b2_1_921600 = 52}
     */
    @EnumMember(
        value = 52L,
        name = "pbn_b2_1_921600"
    )
    pbn_b2_1_921600,

    /**
     * {@code pbn_b2_4_921600 = 53}
     */
    @EnumMember(
        value = 53L,
        name = "pbn_b2_4_921600"
    )
    pbn_b2_4_921600,

    /**
     * {@code pbn_b2_8_921600 = 54}
     */
    @EnumMember(
        value = 54L,
        name = "pbn_b2_8_921600"
    )
    pbn_b2_8_921600,

    /**
     * {@code pbn_b2_8_1152000 = 55}
     */
    @EnumMember(
        value = 55L,
        name = "pbn_b2_8_1152000"
    )
    pbn_b2_8_1152000,

    /**
     * {@code pbn_b2_bt_1_115200 = 56}
     */
    @EnumMember(
        value = 56L,
        name = "pbn_b2_bt_1_115200"
    )
    pbn_b2_bt_1_115200,

    /**
     * {@code pbn_b2_bt_2_115200 = 57}
     */
    @EnumMember(
        value = 57L,
        name = "pbn_b2_bt_2_115200"
    )
    pbn_b2_bt_2_115200,

    /**
     * {@code pbn_b2_bt_4_115200 = 58}
     */
    @EnumMember(
        value = 58L,
        name = "pbn_b2_bt_4_115200"
    )
    pbn_b2_bt_4_115200,

    /**
     * {@code pbn_b2_bt_2_921600 = 59}
     */
    @EnumMember(
        value = 59L,
        name = "pbn_b2_bt_2_921600"
    )
    pbn_b2_bt_2_921600,

    /**
     * {@code pbn_b2_bt_4_921600 = 60}
     */
    @EnumMember(
        value = 60L,
        name = "pbn_b2_bt_4_921600"
    )
    pbn_b2_bt_4_921600,

    /**
     * {@code pbn_b3_2_115200 = 61}
     */
    @EnumMember(
        value = 61L,
        name = "pbn_b3_2_115200"
    )
    pbn_b3_2_115200,

    /**
     * {@code pbn_b3_4_115200 = 62}
     */
    @EnumMember(
        value = 62L,
        name = "pbn_b3_4_115200"
    )
    pbn_b3_4_115200,

    /**
     * {@code pbn_b3_8_115200 = 63}
     */
    @EnumMember(
        value = 63L,
        name = "pbn_b3_8_115200"
    )
    pbn_b3_8_115200,

    /**
     * {@code pbn_b4_bt_2_921600 = 64}
     */
    @EnumMember(
        value = 64L,
        name = "pbn_b4_bt_2_921600"
    )
    pbn_b4_bt_2_921600,

    /**
     * {@code pbn_b4_bt_4_921600 = 65}
     */
    @EnumMember(
        value = 65L,
        name = "pbn_b4_bt_4_921600"
    )
    pbn_b4_bt_4_921600,

    /**
     * {@code pbn_b4_bt_8_921600 = 66}
     */
    @EnumMember(
        value = 66L,
        name = "pbn_b4_bt_8_921600"
    )
    pbn_b4_bt_8_921600,

    /**
     * {@code pbn_panacom = 67}
     */
    @EnumMember(
        value = 67L,
        name = "pbn_panacom"
    )
    pbn_panacom,

    /**
     * {@code pbn_panacom2 = 68}
     */
    @EnumMember(
        value = 68L,
        name = "pbn_panacom2"
    )
    pbn_panacom2,

    /**
     * {@code pbn_panacom4 = 69}
     */
    @EnumMember(
        value = 69L,
        name = "pbn_panacom4"
    )
    pbn_panacom4,

    /**
     * {@code pbn_plx_romulus = 70}
     */
    @EnumMember(
        value = 70L,
        name = "pbn_plx_romulus"
    )
    pbn_plx_romulus,

    /**
     * {@code pbn_oxsemi = 71}
     */
    @EnumMember(
        value = 71L,
        name = "pbn_oxsemi"
    )
    pbn_oxsemi,

    /**
     * {@code pbn_oxsemi_1_15625000 = 72}
     */
    @EnumMember(
        value = 72L,
        name = "pbn_oxsemi_1_15625000"
    )
    pbn_oxsemi_1_15625000,

    /**
     * {@code pbn_oxsemi_2_15625000 = 73}
     */
    @EnumMember(
        value = 73L,
        name = "pbn_oxsemi_2_15625000"
    )
    pbn_oxsemi_2_15625000,

    /**
     * {@code pbn_oxsemi_4_15625000 = 74}
     */
    @EnumMember(
        value = 74L,
        name = "pbn_oxsemi_4_15625000"
    )
    pbn_oxsemi_4_15625000,

    /**
     * {@code pbn_oxsemi_8_15625000 = 75}
     */
    @EnumMember(
        value = 75L,
        name = "pbn_oxsemi_8_15625000"
    )
    pbn_oxsemi_8_15625000,

    /**
     * {@code pbn_intel_i960 = 76}
     */
    @EnumMember(
        value = 76L,
        name = "pbn_intel_i960"
    )
    pbn_intel_i960,

    /**
     * {@code pbn_sgi_ioc3 = 77}
     */
    @EnumMember(
        value = 77L,
        name = "pbn_sgi_ioc3"
    )
    pbn_sgi_ioc3,

    /**
     * {@code pbn_computone_4 = 78}
     */
    @EnumMember(
        value = 78L,
        name = "pbn_computone_4"
    )
    pbn_computone_4,

    /**
     * {@code pbn_computone_6 = 79}
     */
    @EnumMember(
        value = 79L,
        name = "pbn_computone_6"
    )
    pbn_computone_6,

    /**
     * {@code pbn_computone_8 = 80}
     */
    @EnumMember(
        value = 80L,
        name = "pbn_computone_8"
    )
    pbn_computone_8,

    /**
     * {@code pbn_sbsxrsio = 81}
     */
    @EnumMember(
        value = 81L,
        name = "pbn_sbsxrsio"
    )
    pbn_sbsxrsio,

    /**
     * {@code pbn_pasemi_1682M = 82}
     */
    @EnumMember(
        value = 82L,
        name = "pbn_pasemi_1682M"
    )
    pbn_pasemi_1682M,

    /**
     * {@code pbn_ni8430_2 = 83}
     */
    @EnumMember(
        value = 83L,
        name = "pbn_ni8430_2"
    )
    pbn_ni8430_2,

    /**
     * {@code pbn_ni8430_4 = 84}
     */
    @EnumMember(
        value = 84L,
        name = "pbn_ni8430_4"
    )
    pbn_ni8430_4,

    /**
     * {@code pbn_ni8430_8 = 85}
     */
    @EnumMember(
        value = 85L,
        name = "pbn_ni8430_8"
    )
    pbn_ni8430_8,

    /**
     * {@code pbn_ni8430_16 = 86}
     */
    @EnumMember(
        value = 86L,
        name = "pbn_ni8430_16"
    )
    pbn_ni8430_16,

    /**
     * {@code pbn_ADDIDATA_PCIe_1_3906250 = 87}
     */
    @EnumMember(
        value = 87L,
        name = "pbn_ADDIDATA_PCIe_1_3906250"
    )
    pbn_ADDIDATA_PCIe_1_3906250,

    /**
     * {@code pbn_ADDIDATA_PCIe_2_3906250 = 88}
     */
    @EnumMember(
        value = 88L,
        name = "pbn_ADDIDATA_PCIe_2_3906250"
    )
    pbn_ADDIDATA_PCIe_2_3906250,

    /**
     * {@code pbn_ADDIDATA_PCIe_4_3906250 = 89}
     */
    @EnumMember(
        value = 89L,
        name = "pbn_ADDIDATA_PCIe_4_3906250"
    )
    pbn_ADDIDATA_PCIe_4_3906250,

    /**
     * {@code pbn_ADDIDATA_PCIe_8_3906250 = 90}
     */
    @EnumMember(
        value = 90L,
        name = "pbn_ADDIDATA_PCIe_8_3906250"
    )
    pbn_ADDIDATA_PCIe_8_3906250,

    /**
     * {@code pbn_ce4100_1_115200 = 91}
     */
    @EnumMember(
        value = 91L,
        name = "pbn_ce4100_1_115200"
    )
    pbn_ce4100_1_115200,

    /**
     * {@code pbn_omegapci = 92}
     */
    @EnumMember(
        value = 92L,
        name = "pbn_omegapci"
    )
    pbn_omegapci,

    /**
     * {@code pbn_NETMOS9900_2s_115200 = 93}
     */
    @EnumMember(
        value = 93L,
        name = "pbn_NETMOS9900_2s_115200"
    )
    pbn_NETMOS9900_2s_115200,

    /**
     * {@code pbn_brcm_trumanage = 94}
     */
    @EnumMember(
        value = 94L,
        name = "pbn_brcm_trumanage"
    )
    pbn_brcm_trumanage,

    /**
     * {@code pbn_fintek_4 = 95}
     */
    @EnumMember(
        value = 95L,
        name = "pbn_fintek_4"
    )
    pbn_fintek_4,

    /**
     * {@code pbn_fintek_8 = 96}
     */
    @EnumMember(
        value = 96L,
        name = "pbn_fintek_8"
    )
    pbn_fintek_8,

    /**
     * {@code pbn_fintek_12 = 97}
     */
    @EnumMember(
        value = 97L,
        name = "pbn_fintek_12"
    )
    pbn_fintek_12,

    /**
     * {@code pbn_fintek_F81504A = 98}
     */
    @EnumMember(
        value = 98L,
        name = "pbn_fintek_F81504A"
    )
    pbn_fintek_F81504A,

    /**
     * {@code pbn_fintek_F81508A = 99}
     */
    @EnumMember(
        value = 99L,
        name = "pbn_fintek_F81508A"
    )
    pbn_fintek_F81508A,

    /**
     * {@code pbn_fintek_F81512A = 100}
     */
    @EnumMember(
        value = 100L,
        name = "pbn_fintek_F81512A"
    )
    pbn_fintek_F81512A,

    /**
     * {@code pbn_wch382_2 = 101}
     */
    @EnumMember(
        value = 101L,
        name = "pbn_wch382_2"
    )
    pbn_wch382_2,

    /**
     * {@code pbn_wch384_4 = 102}
     */
    @EnumMember(
        value = 102L,
        name = "pbn_wch384_4"
    )
    pbn_wch384_4,

    /**
     * {@code pbn_wch384_8 = 103}
     */
    @EnumMember(
        value = 103L,
        name = "pbn_wch384_8"
    )
    pbn_wch384_8,

    /**
     * {@code pbn_sunix_pci_1s = 104}
     */
    @EnumMember(
        value = 104L,
        name = "pbn_sunix_pci_1s"
    )
    pbn_sunix_pci_1s,

    /**
     * {@code pbn_sunix_pci_2s = 105}
     */
    @EnumMember(
        value = 105L,
        name = "pbn_sunix_pci_2s"
    )
    pbn_sunix_pci_2s,

    /**
     * {@code pbn_sunix_pci_4s = 106}
     */
    @EnumMember(
        value = 106L,
        name = "pbn_sunix_pci_4s"
    )
    pbn_sunix_pci_4s,

    /**
     * {@code pbn_sunix_pci_8s = 107}
     */
    @EnumMember(
        value = 107L,
        name = "pbn_sunix_pci_8s"
    )
    pbn_sunix_pci_8s,

    /**
     * {@code pbn_sunix_pci_16s = 108}
     */
    @EnumMember(
        value = 108L,
        name = "pbn_sunix_pci_16s"
    )
    pbn_sunix_pci_16s,

    /**
     * {@code pbn_titan_1_4000000 = 109}
     */
    @EnumMember(
        value = 109L,
        name = "pbn_titan_1_4000000"
    )
    pbn_titan_1_4000000,

    /**
     * {@code pbn_titan_2_4000000 = 110}
     */
    @EnumMember(
        value = 110L,
        name = "pbn_titan_2_4000000"
    )
    pbn_titan_2_4000000,

    /**
     * {@code pbn_titan_4_4000000 = 111}
     */
    @EnumMember(
        value = 111L,
        name = "pbn_titan_4_4000000"
    )
    pbn_titan_4_4000000,

    /**
     * {@code pbn_titan_8_4000000 = 112}
     */
    @EnumMember(
        value = 112L,
        name = "pbn_titan_8_4000000"
    )
    pbn_titan_8_4000000,

    /**
     * {@code pbn_moxa_2 = 113}
     */
    @EnumMember(
        value = 113L,
        name = "pbn_moxa_2"
    )
    pbn_moxa_2,

    /**
     * {@code pbn_moxa_4 = 114}
     */
    @EnumMember(
        value = 114L,
        name = "pbn_moxa_4"
    )
    pbn_moxa_4,

    /**
     * {@code pbn_moxa_8 = 115}
     */
    @EnumMember(
        value = 115L,
        name = "pbn_moxa_8"
    )
    pbn_moxa_8
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct pci_bits"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class pci_bits extends Struct {
    public @Unsigned int reg;

    public @Unsigned int width;

    public @Unsigned long mask;

    public @Unsigned long val;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct pci_check_idx_range"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class pci_check_idx_range extends Struct {
    public int start;

    public int end;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct pci_raw_ops"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class pci_raw_ops extends Struct {
    public Ptr<?> read;

    public Ptr<?> write;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct pci_mmcfg_hostbridge_probe"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class pci_mmcfg_hostbridge_probe extends Struct {
    public @Unsigned int bus;

    public @Unsigned int devfn;

    public @Unsigned int vendor;

    public @Unsigned int device;

    public Ptr<?> probe;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct pci_root_info"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class pci_root_info extends Struct {
    public acpi_pci_root_info common;

    public pci_sysdata sd;

    public boolean mcfg_added;

    public char start_bus;

    public char end_bus;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "enum pci_bf_sort_state"
  )
  public enum pci_bf_sort_state implements Enum<pci_bf_sort_state>, TypedEnum<pci_bf_sort_state, java.lang. @Unsigned Integer> {
    /**
     * {@code pci_bf_sort_default = 0}
     */
    @EnumMember(
        value = 0L,
        name = "pci_bf_sort_default"
    )
    pci_bf_sort_default,

    /**
     * {@code pci_force_nobf = 1}
     */
    @EnumMember(
        value = 1L,
        name = "pci_force_nobf"
    )
    pci_force_nobf,

    /**
     * {@code pci_force_bf = 2}
     */
    @EnumMember(
        value = 2L,
        name = "pci_force_bf"
    )
    pci_force_bf,

    /**
     * {@code pci_dmi_bf = 3}
     */
    @EnumMember(
        value = 3L,
        name = "pci_dmi_bf"
    )
    pci_dmi_bf
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct pci_setup_rom"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class pci_setup_rom extends Struct {
    public setup_data data;

    public @Unsigned @OriginalName("uint16_t") short vendor;

    public @Unsigned @OriginalName("uint16_t") short devid;

    public @Unsigned @OriginalName("uint64_t") long pcilen;

    public @Unsigned long segment;

    public @Unsigned long bus;

    public @Unsigned long device;

    public @Unsigned long function;

    public @OriginalName("uint8_t") char @Size(0) [] romdata;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct pci_root_res"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class pci_root_res extends Struct {
    public list_head list;

    public resource res;
  }
}
